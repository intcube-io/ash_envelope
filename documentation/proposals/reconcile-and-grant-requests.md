# Proposal — `AshEnvelope.Reconcile` + `AshEnvelope.GrantRequests`

Status: phases 1–4 implemented (`AshEnvelope.GrantRequests`, `AshEnvelope.Reconcile` extension with the `affects do … end` DSL, full `granter_chain` including `:any_authorized` + `:request`, `Reconcile.Runner`, `Reconcile.Changes.SyncSubject`/`.SyncPrincipal`, decoupled from `AshEnvelope.Storage`). Async (phase 5) and the auto-derive layer (Future work) are still open.

This proposal adds two cooperating pieces to `ash_envelope`:

1. **`AshEnvelope.Reconcile`** — a Spark extension that wires up the lifecycle
   of grants automatically. The host application declares which "affecting"
   resources (memberships, role attributes, etc.) influence read authorization
   on the encrypted resource; the extension installs the after-action changes
   that keep the grants table in sync, using `Ash.can?/3` against the
   encrypted resource's read policy as the single source of truth.

2. **`AshEnvelope.GrantRequests`** — a sibling primitive to `KeyGrants` that
   captures pending "please grant me access" rows when the actor triggering an
   authorization-changing action does not themselves hold a grant on the
   subject (and therefore cannot wrap the DEK to the new recipient). Any
   future authorized user can fulfill the pending request, either eagerly
   (e.g. on the next read of an encrypted resource) or lazily (background
   worker, admin UI panel).

The motivating evidence is in the `roadmapp3r` integration: four custom Ash
change modules — `ShareWithRecipients`, `GrantOrgEvidence`/`RevokeOrgEvidence`,
`SyncAdminGrants`, `SyncEvidenceGrants` — implement the same algorithm:

> For each `(user, encrypted_record)` pair in some scope, ask
> `Ash.can?(:read, record, actor: user)`; if `true` and no grant exists,
> create one; if `false` and a grant exists, delete it.

This belongs as one extension. Each downstream change module collapses into
a 4-line DSL block.

---

## Concepts

- **Subject**: a row of the encrypted resource (e.g. an Evidence file). The
  thing whose DEK is wrapped per principal.
- **Principal**: a user/actor row. Has an X25519 public key (always) and a
  private key (loadable when they're the actor of a request).
- **Grant**: a row in the `KeyGrants` table — `(subject_id, principal_id,
  wrapped_dek)`. Authorizes one principal to decrypt one subject.
- **Affecting resource**: any resource whose lifecycle changes the result of
  `Ash.can?(:read, subject, actor: principal)`. Memberships are the canonical
  case; role attributes on the user resource are another.
- **Granter**: any principal who can re-wrap the DEK for a new recipient. They
  must satisfy two conditions: (1) hold an existing grant on the subject and
  (2) have a usable private key on hand at the time of the share.
- **Grant request**: a row in the `GrantRequests` table — `(subject_id,
  target_principal_id, requested_at, requested_by_id, …)`. Means "the system
  decided this principal should have a grant, but the actor at the time
  couldn't issue it." Fulfilled later by any authorized principal.

---

## DSL surface

### On the encrypted resource

```elixir
defmodule MyApp.Document do
  use Ash.Resource, extensions: [AshEnvelope.Storage, AshEnvelope.Reconcile]

  encryption do
    actor_public_key_attribute :encryption_public_key
    actor_private_key_attribute :encryption_private_key
    key_grants_resource MyApp.DocumentKeyGrant
    key_grants_subject_id_attribute :blob_id
    domain MyApp.Catalog
  end

  reconcile do
    # Optional. When set, unsatisfiable grants are written here for later
    # fulfillment instead of being silently dropped.
    grant_requests_resource MyApp.GrantRequest

    # Order in which to look for a granter. Default: [:actor, :request].
    # Available strategies:
    #   :actor             — the actor of the triggering changeset (must hold a grant + private key)
    #   :any_authorized    — any principal whose Ash.can?(:read, …) returns true and who has a key path
    #   :request           — fall back to creating a grant request (needs grant_requests_resource)
    #   {Mod, :fun}        — custom `fun(config, subject_id, target_user, ctx) :: {:ok, granter} | :error`
    granter_chain [:actor, :request]

    # Each `affects` declares: when these actions on this resource fire, the
    # named users may have changed authorization on subjects matching `scope`.
    affects MyApp.Membership do
      actions [:create, :update, :destroy]
      principal :user_id
      scope {:filter, fn cs -> [org_id: Ash.Changeset.get_data(cs, :org_id)] end}
    end

    affects MyApp.MultiplicatorMembership do
      actions [:create, :update, :destroy]
      principal :user_id

      scope {:filter,
             fn cs ->
               m_id =
                 Ash.Changeset.get_data(cs, :multiplicator_id) ||
                   Ash.Changeset.get_attribute(cs, :multiplicator_id)

               Ash.Query.filter(MyApp.Document,
                 exists(org.multiplicator_org_memberships, multiplicator_id == ^m_id)
               )
             end}
    end

    affects MyApp.User do
      actions [:create, :update]
      principal :id
      scope :all
      only_when fn cs -> Ash.Changeset.changing_attribute?(cs, :role) end
    end

    # Optional. When :async is true, reconciliation runs in an Oban job.
    # Requires :ash_oban; defaults to :sync.
    mode :sync
  end
end
```

### On the affecting resources

Nothing. The `affects` block in `MyApp.Document` causes the extension's
transformer to install a single after-action change on each affecting
resource's matching actions. Host code does not need to add changes itself.

---

## Module layout (proposed)

```
lib/ash_envelope/reconcile.ex                                 # Spark extension + DSL
lib/ash_envelope/reconcile/info.ex                            # Spark.InfoGenerator
lib/ash_envelope/reconcile/runner.ex                          # core algorithm
lib/ash_envelope/reconcile/changes/sync_subject.ex            # injected on encrypted resource (after attach/create)
lib/ash_envelope/reconcile/changes/sync_principal.ex          # injected on each affecting resource
lib/ash_envelope/reconcile/transformers/install_changes.ex    # walks affects[], installs sync_principal
lib/ash_envelope/reconcile/granter.ex                         # implements granter strategies
lib/ash_envelope/grant_requests.ex                            # public API, mirrors KeyGrants
lib/ash_envelope/grant_requests/config.ex                     # struct, mirrors KeyGrants.Config
lib/mix/tasks/ash_envelope.gen.grant_requests.ex              # scaffolding generator
```

`Reconcile` and `GrantRequests` are independently useful. `Reconcile` only
depends on `GrantRequests` if a grant_requests_resource is configured.

---

## Algorithm: `Reconcile.Runner.run/3`

Entry point used by both `sync_subject` and `sync_principal`:

```elixir
@spec run(
  config :: Config.t(),     # combined: KeyGrants.Config + reconcile DSL options
  pairs :: [{principal_id, subject_id}],
  ctx :: Context.t()        # actor, domain, changeset, action_type
) :: :ok
```

For each `{principal_id, subject_id}` pair:

1. **Load `principal`** with `select: [:id, public_key_attr]` (and
   `:role` if any granter strategy needs it).
2. **Load `subject`** with whatever's needed for the `:read` policy
   (typically the resource itself + minimal relations).
3. **`should?` = `Ash.can?({subject, :read}, principal, domain: ctx.domain)`**.
4. **`has?` = grant lookup** for `(subject_id, principal_id)` on the
   configured grants resource.
5. Diff:
   - `should? and not has?` → call `grant/4`.
   - `not should? and has?` → call `revoke/4`.
   - else: no-op.

`grant/4` walks the configured `granter_chain`:

| Step | Strategy | Behaviour |
|---|---|---|
| 1 | `:actor` | If `ctx.actor` has a grant on `subject_id` *and* their private-key attribute is loadable: call `KeyGrants.share(config, subject_id, ctx.actor, principal, domain)`. |
| 2 | `:any_authorized` | Find any principal `g` with a grant on `subject_id` and a loadable private key, where `Ash.can?({subject, :read}, g, …)` is true. Same `share/5` call. |
| 3 | `:request` | Insert a `GrantRequest` row `(subject_id, target_principal_id, requested_by: ctx.actor.id)`. |

If the chain is exhausted with no success, log a warning and continue (the
`revoke/4` half is unaffected — revocations never need a granter).

`revoke/4` deletes the grant row(s) and any unfulfilled grant requests for
the same `(subject_id, principal_id)`.

---

## Pair enumeration

`sync_subject` (after creating/updating an encrypted record):

- pairs = `{candidate_user_id, this_subject_id}` for every user in the
  resource's authorization graph (admins, members, multiplicator viewers,
  backup recipients, etc.). The DSL doesn't need to spell this out — the
  extension does a broad `Ash.can?` filter at runtime over a candidate set
  loaded by walking the read policy's referenced relationships, OR (simpler
  for v1) the host app declares a `candidates` callback:

  ```elixir
  reconcile do
    candidates fn _subject ->
      Ash.Query.filter(MyApp.User, true)   # then filtered through Ash.can?
    end
  end
  ```

  The default candidate set is "all users", which is correct but slow. Most
  apps will want to narrow it.

`sync_principal` (after a membership/role change):

- pairs = `{principal_id, subject_id}` for every subject matching the
  `scope` of this `affects` clause. The scope is evaluated against
  `MyApp.Document` (the encrypted resource); the result is a list of
  subjects to reconcile this one principal against.

The two paths share `Runner.run/3` once they've materialized their pair
list.

---

## `GrantRequests` resource pattern

Mirrors `KeyGrants` exactly: a `Config` struct, a `gen.grant_requests` mix
task, and a public API:

```elixir
%AshEnvelope.GrantRequests.Config{
  resource: MyApp.GrantRequest,
  subject_id_attribute: :blob_id,
  target_principal_id_attribute: :user_id,
  requested_by_attribute: :requested_by_id,
  fulfilled_at_attribute: :fulfilled_at,
  fulfilled_by_attribute: :fulfilled_by_id
}
```

Public ops:

```elixir
# Reconcile.Runner uses this when the granter chain falls back to :request.
GrantRequests.create(config, subject_id, target_user, requested_by, domain)

# Called by host code to surface pending requests an actor could fulfill.
# Returns rows where: not fulfilled AND actor has a grant on subject_id.
GrantRequests.list_fulfillable_for(config, key_grants_config, actor, domain)

# Atomic: re-wraps DEK from `actor` to `target_user`, marks request fulfilled.
# Idempotent against concurrent fulfillment (uses a fulfilled_at check).
GrantRequests.fulfill(config, key_grants_config, request, actor, domain)

# Convenience: fulfill every request the actor could fulfill, returning a
# count. Cheap to call on login or per-request hot paths.
GrantRequests.fulfill_outstanding(config, key_grants_config, actor, domain)
```

The grant_requests resource itself is a normal Ash resource, with a
unique-where-pending identity:

```elixir
identity :unique_pending,
  [:subject_id, :target_principal_id],
  where: expr(is_nil(fulfilled_at))
```

…so duplicate requests collapse without raising.

---

## How this collapses downstream code

In `roadmapp3r` today (post-implementation):

```
lib/roadmapp3r_ash/assessments/evidence/changes/share_with_recipients.ex
lib/roadmapp3r_ash/assessments/user_org_membership/changes/grant_org_evidence.ex
lib/roadmapp3r_ash/assessments/user_org_membership/changes/revoke_org_evidence.ex
lib/roadmapp3r_ash/accounts/user/changes/sync_admin_grants.ex
lib/roadmapp3r_ash/assessments/user_multiplicator_membership/changes/sync_evidence_grants.ex
```

…all five files disappear, replaced by the `reconcile do … end` block on
`Roadmapp3rAsh.Assessments.Evidence`. The `actor_can_access_via_multiplicator`
calculation and the multiplicator clause in the read policy stay (they're
the policy itself, which is what `Ash.can?` consults). The downstream
`Ash.can?`-driven design we just settled on becomes the *only* path —
correct by construction.

The custom `Roadmapp3rAsh.Assessments.EncryptedStorageService` would still
exist as a downstream override of `AshEnvelope.Storage.Encrypted` until the
upstream `service.upload :: :ok` contract issue with `AshStorage` is
resolved (out of scope here).

---

## Open design questions

1. **Pair enumeration cost on `sync_subject`**: walking "all users" through
   `Ash.can?` is O(n). Acceptable for small N; bad at scale. The
   `candidates` callback gives the host app an escape hatch, but a smarter
   default — analyze the read policy's reference graph at compile time and
   build a narrowed query — would be a worthwhile follow-up.

2. **`only_when` semantics**: should it gate just the after-action, or
   short-circuit the whole pair enumeration? Probably the latter, for
   performance.

3. **Scope shape**: `{:filter, fn cs -> filter_or_query end}`. Filters
   compose cleanly; full queries let the host order/limit. Both should be
   accepted.

4. **Async (`mode :async`)**: requires `ash_oban`. The runner's input is
   serializable (config + pair list + actor id), so swapping in an Oban job
   is mechanical. v1 ships sync; async added later.

5. **Backup recipient handling**: the backup user is a degenerate granter
   (public key only, no private key on hand). They should never appear as
   a candidate granter, only as a recipient. The `granter` strategy
   implementations need to filter on "private key loadable" — typically
   via the configured cloak path or a host-supplied callback.

6. **`KeyGrants.share/5` actor shape**: today the granting actor must carry
   both `:public_key` and `:private_key` attributes. `Reconcile` will load
   them via `Ash.load!(actor, [private_key_attr])` (the cloak calc); the
   public key is non-sensitive and already on the user struct. Document
   this assumption in `KeyGrants` itself.

7. **What if the actor IS the target?** (E.g. `User.update` where the user
   updates their own role.) The actor and target are the same principal;
   the `:actor` strategy can't help (you can't share to yourself from
   yourself if you don't already have the grant). The `:any_authorized`
   strategy handles this. Spell out in docs.

8. **Grant requests UX**: the library provides primitives, not UI. Most
   apps will want either (a) a "pending requests" admin panel that calls
   `fulfill_outstanding/4` on demand, or (b) a hook in their auth pipeline
   that calls it on every authenticated request. Document both patterns.

---

## Implementation phases

A phased rollout keeps each PR reviewable:

1. **`GrantRequests` primitive + config + tests** (mirrors `KeyGrants`).
   Self-contained, mergeable independently. Generator task.
2. **`Reconcile` extension skeleton**: DSL parses, but the runner is just
   `:actor` strategy + scope `:all`. Tests with synthetic resources.
3. **Pair enumeration via `affects do … end` and `candidates`**.
4. **`granter_chain` with `:any_authorized` + `:request` strategies**.
5. **`mode :async` via Oban (optional dep)**.
6. **Documentation**: a "Reconciliation" topic and a tutorial showing the
   end-to-end membership-driven setup.
7. **Migration of `roadmapp3r` to the new extension** (downstream),
   deleting the five custom change modules.

Each phase ends with green CI and a hex release candidate. Phases 1–4 are
the minimum viable replacement for the downstream code.

---

## Out of scope

- A full pending-requests UI library. The library exposes lookups; UI is
  the host's problem.
- Cross-domain reconciliation (the encrypted resource and affecting
  resources must currently share a domain).
- Reconciling against authorization rules other than Ash policies. The
  whole design assumes `Ash.can?` is the truth.
- Fixing the upstream `AshStorage` `service.upload :: :ok` contract issue
  that forced the downstream `EncryptedStorageService` workaround.

---

## Future work — auto-derive `affects` from the read policy

The manual `affects` DSL is the v1 surface. A natural follow-up is to
derive the same `affects` plan automatically by walking the encrypted
resource's `:read` policy AST at compile time. The host then writes:

```elixir
reconcile do
  grant_requests_resource MyApp.GrantRequest
  granter_chain [:actor, :request]
  # No affects blocks in the common case — auto-derived from the read policy.

  # Explicit overrides for opaque pieces:
  affects MyApp.SomeCustomCheck do
    via MyApp.UserOrgMembership
    principal :user_id
    scope {:filter, fn cs -> [org_id: Ash.Changeset.get_attribute(cs, :org_id)] end}
  end

  ignore MyApp.NoisyJoinTable
end
```

### Derivable elements (mechanical)

| Policy element | Derives → |
|---|---|
| `actor_attribute_equals(:role, :backup)` | "User.role affects authz" → after-action on `User.create`/`update`. The runner re-evaluates `Ash.can?` so no `only_when` is strictly needed; an explicit one keeps the noise down. |
| `relates_to_actor_via([:org, :user_org_memberships, :user])` | The join resource on the path (`UserOrgMembership`) becomes affecting. Principal = the FK to the actor type (`:user_id`). Scope = inverse traversal: filter the encrypted resource by the FK on the other side of the join (`org_id`). |
| `expr(some_calculation == true)` | Recurse into the calculation's `expr`. References inside expand the same way (relationships → join resources, attributes → User attribute filters). |

### Non-derivable elements

These need either an explicit `affects` block or a new opt-in callback on
the check module:

- **Custom `Ash.Policy.SimpleCheck` modules** — opaque `match?/3` body.
- **`expr(host_function(...))`** policies that call user-defined functions.
- **Filter-based bypasses** with dynamic queries.

The cleanest opt-in is a behaviour on the check module itself, since the
check already knows what it reads:

```elixir
defmodule MyApp.Checks.OrgMemberCheck do
  use Ash.Policy.SimpleCheck
  @behaviour AshEnvelope.Reconcile.Affects

  @impl AshEnvelope.Reconcile.Affects
  def affects do
    [
      {MyApp.UserOrgMembership,
       principal: :user_id,
       scope: {:filter, fn cs -> [org_id: Ash.Changeset.get_attribute(cs, :org_id)] end}}
    ]
  end

  # … existing match?/3 …
end
```

The transformer detects the behaviour and folds the returned entries into
the derived plan.

### Compile-time visibility

A mix task prints the derived plan so it's never surprising:

```
$ mix ash_envelope.reconcile.show MyApp.Document

MyApp.Document reconciliation plan
==================================
Affecting resources (auto-derived):
  MyApp.User
    actions:    [:create, :update]
    only_when:  changing_attribute?(:role)
    principal:  :id
    scope:      :all
  MyApp.UserOrgMembership
    actions:    [:create, :update, :destroy]
    principal:  :user_id
    scope:      filter(org_id == ^cs.data.org_id)
  …

Unanalyzable policy elements (require explicit affects or behaviour):
  none
```

A companion `mix ash_envelope.reconcile.diff` compares the derived plan
to a committed snapshot file, so a downstream policy edit that quietly
broadens the affected resource set surfaces as a checked-in diff during
code review.

If an unanalyzable element has no override, the transformer raises a
`Spark.Error.DslError` at compile time with a hint about both fixes
(explicit `affects` or `@behaviour AshEnvelope.Reconcile.Affects`).

### Trade-offs

- **Pro: single source of truth.** Policy edit ⇒ grant lifecycle follows.
- **Pro: less boilerplate.** Most apps end up with an empty `reconcile`
  block plus `grant_requests_resource`.
- **Con: surprise factor.** A policy edit can silently widen the
  affecting set. Mitigated by `reconcile.show` and `reconcile.diff`.
- **Con: implementation cost.** Walking the policy AST + handling check
  callbacks is real work. Worth deferring until the manual surface has
  shaken out in practice.

### Implementation outline (when picked up)

1. `lib/ash_envelope/reconcile/policy_analyzer.ex` — walks
   `Ash.Policy.Info.policies(resource, :read)` and produces the derived
   `[Affects.t()]` list. Handles `actor_attribute_equals/in/contains`,
   `relates_to_actor_via`, `expr(...)` with calculation lookup, and the
   `Affects` behaviour.
2. `lib/ash_envelope/reconcile/transformers/install_changes.ex` — merges
   derived entries with explicit `affects` blocks (explicit wins on
   conflict). `ignore` removes derived entries.
3. `lib/mix/tasks/ash_envelope.reconcile.show.ex` — pretty-prints the
   merged plan.
4. `lib/mix/tasks/ash_envelope.reconcile.diff.ex` — compares against a
   committed `ash_envelope_reconcile.snapshot` file.
5. Validation pass that raises on unanalyzable elements lacking overrides.
6. Tutorial / topic updates demonstrating both styles side by side.

This phase is independent of the manual surface — both can coexist
indefinitely. The auto-derive layer is purely additive.
