# Reconciliation

> Future work — auto-derive `affects` from the encrypted resource's
> `:read` policy AST (custom `Ash.Policy.SimpleCheck` modules opt in via
> a behaviour). See the
> [Reconcile design proposal](../proposals/reconcile-and-grant-requests.md)
> for the full sketch.

`AshEnvelope.Reconcile` keeps a `KeyGrants` table in sync with the
encrypted resource's `:read` policy. As users join orgs, change roles,
or get added to multiplicators, the matching grants on every affected
record are created or destroyed automatically — without writing one-off
"sync grants" change modules per relationship.

The truth is `Ash.can?(:read, subject, actor: principal)`. If the
policy authorizes the principal but no grant exists, the runner walks a
configured `granter_chain` to issue one. If a grant exists but the
policy no longer authorizes the principal, the runner destroys it (and
clears any pending grant request).

## Quick start

### 1. Configure the encrypted resource

Declare every "affecting" resource in a single `affects do … end` block
on the encrypted resource. Each entry is the source of truth for the
principal/scope/only_when that `SyncPrincipal` will use on the
affecting side:

```elixir
defmodule MyApp.Document do
  use Ash.Resource,
    extensions: [AshStorage, AshEnvelope.Reconcile]

  storage do
    service {AshStorage.Service.S3, bucket: "private-blobs"}
    blob_resource MyApp.DocumentBlob
    attachment_resource MyApp.DocumentAttachment

    layer {AshStorage.Layer.Encryption,
           key_manager:
             {AshEnvelope.BlobIO.KeyManagers.KeyGrants,
              grants_resource: MyApp.DocumentKeyGrant,
              domain: MyApp.Catalog,
              actor_public_key_attribute: :encryption_public_key,
              actor_private_key_attribute: :encryption_private_key,
              subject_id_attribute: :blob_id},
           proxy_base_url: "/storage"},
          metadata_key: "documents"

    has_one_attached :file
  end

  reconcile do
    user_resource MyApp.User
    domain MyApp.Catalog
    key_grants_resource MyApp.DocumentKeyGrant
    key_grants_subject_id_attribute :blob_id
    actor_public_key_attribute :encryption_public_key
    actor_private_key_attribute :encryption_private_key
    grant_requests_resource MyApp.DocumentGrantRequest
    granter_chain [:actor, :request]
    user_load [:encryption_private_key]

    affects MyApp.Membership do
      actions [:create, :update, :destroy]
      principal :user_id

      scope fn cs ->
        [org_id: Ash.Changeset.get_attribute(cs, :org_id) ||
                 Ash.Changeset.get_data(cs, :org_id)]
      end
    end

    affects MyApp.User do
      actions [:update]
      principal :id
      scope :all
      only_when fn cs -> Ash.Changeset.changing_attribute?(cs, :role) end
    end
  end
end
```

`grant_requests_resource` is required iff `:request` appears in the
chain. Generate it with:

```bash
mix ash_envelope.gen.grant_requests MyApp.Document \
  --requests-resource MyApp.DocumentGrantRequest \
  --grants-resource MyApp.DocumentKeyGrant \
  --domain MyApp.Catalog \
  --user-resource MyApp.User
```

### Required fields

`domain`, `key_grants_resource`, `actor_public_key_attribute`, and
`actor_private_key_attribute` are required and must be set in
`reconcile do`. Compile-time validation is performed by
`AshEnvelope.Reconcile.Transformers.ValidateConfig`.

When the encrypted resource is an AshStorage attachment using the
`KeyGrants` BlobIO key manager (as above), the same grants resource is
referenced on both sides. Keep the values in `reconcile do` and the
key-manager opts in sync — they read and write the same table.

### 2. Install the change on each affecting resource

For every resource whose lifecycle changes who can read a `Document`,
add a one-line `SyncPrincipal` change. The change resolves the
matching `affects __MODULE__` entry on `MyApp.Document` at runtime, so
neither principal nor scope are repeated:

```elixir
defmodule MyApp.Membership do
  use Ash.Resource, ...

  actions do
    create :create do
      accept [:user_id, :org_id]
      change {AshEnvelope.Reconcile.Changes.SyncPrincipal,
              encrypted_resource: MyApp.Document}
    end

    destroy :destroy do
      change {AshEnvelope.Reconcile.Changes.SyncPrincipal,
              encrypted_resource: MyApp.Document}
    end
  end
end
```

When the action's name isn't listed in the affects entry's `actions`,
the change is a silent no-op — useful for actions you intentionally
want to skip.

#### Explicit overrides

Pass `principal:`/`scope:`/`only_when:` directly to the change to
override (or bypass) the lookup. Useful when the affecting resource
lives outside the host's control or when one action wants different
semantics than the declared `affects` entry:

```elixir
update :update do
  accept [:role, :name]

  change {AshEnvelope.Reconcile.Changes.SyncPrincipal,
          encrypted_resource: MyApp.Document,
          principal: :id,
          scope: :all,
          only_when: fn cs -> Ash.Changeset.changing_attribute?(cs, :role) end}
end
```

### 3. (Optional) Install `SyncSubject` on the encrypted resource

If you create or rotate subjects in code paths that don't go through
the BlobIO encryption layer's attach (e.g. seed data, migrations),
install `SyncSubject` on the encrypted resource so existing principals
get fanned out automatically:

```elixir
update :update do
  change AshEnvelope.Reconcile.Changes.SyncSubject

  # Or with a narrower candidate set:
  change {AshEnvelope.Reconcile.Changes.SyncSubject,
          candidates: fn _subject ->
            Ash.Query.filter(MyApp.User, role in [:admin, :user])
          end}
end
```

## Granter chain

Strategies are tried in order. Each returns `:ok` (granted), `:skip`
(try next), or `{:error, reason}`.

| Strategy | Behaviour |
|---|---|
| `{:dek_from_process, key_for: fun}` | Bootstrap a grant from a freshly-generated DEK stashed in the process dictionary by the encryption pipeline. `fun.(subject_record)` returns the storage key. |
| `:actor` | Actor of the triggering changeset re-wraps the DEK. Requires the actor to hold a grant on the subject AND have their private key field populated. |
| `:request` | Write a pending row to `grant_requests_resource`. Fulfilled later by `AshEnvelope.GrantRequests.fulfill_outstanding/5`. |

Default chain is `[:actor, :request]`. Tuple-form strategies accept a
`:when` predicate (`(target, ctx) -> boolean`) to gate which targets
they fire for — see the moduledoc for `AshEnvelope.Reconcile.Granter`.

## Preview & confirm

By default reconciliation fires in `after_transaction` and writes
grants/revocations directly. For a confirmation UX, call `Runner.plan/2`
yourself before triggering the change to render a "you're about to
grant access to N people, confirm?" dialog, then call `Runner.apply_plan!/3`
on confirm:

```elixir
{:ok, ctx} = AshEnvelope.Reconcile.Info.context(MyApp.Document)
ctx = %{ctx | actor: current_user}
pairs = build_pairs_for_change(changeset)
plan = AshEnvelope.Reconcile.Runner.plan(ctx, pairs)

if AshEnvelope.Reconcile.Plan.empty?(plan) do
  :ok  # nothing to confirm
else
  stash_for_confirmation(plan)
end
```

On confirm: `AshEnvelope.Reconcile.Runner.apply_plan!(ctx, plan)`.

`apply_plan!/3` wraps the writes in `Ash.transaction/2` by default so
the batch is atomic across the grant inserts/deletes. Pass
`transaction: false` if you've already opened a transaction yourself.

### Return value

`Runner.run/3` and `Runner.apply_plan!/3` return `:ok` only when every
planned grant and revocation applied cleanly. Otherwise they return
`{:error, aggregate}` where `aggregate` is a map with:

- `:grant_failures` — `[{principal_id, subject_id, reason}]` for grant
  entries whose granter chain errored,
- `:revoke_failures` — `[{principal_id, subject_id, reason}]` for
  revocations that failed (grant read, grant destroy, or pending-request
  cleanup),
- `:plan_errors` — `[{principal_id, reason}]` carried over from
  `Plan.errors` (pairs that errored during planning).

An exhausted granter chain (every strategy returned `:skip`) is logged
but not counted as a failure.

How a failure surfaces depends on where reconciliation runs:

- **`:sync` mode** — the change modules fire in `after_transaction`,
  after the host write has committed, so they log the aggregate at
  `:warning` and return the host action's original result (best-effort).
  Call `Runner.run/3` directly when you need to handle the aggregate.
- **`:async` mode** — `AsyncWorker.perform/1` returns the aggregate to
  Oban, which retries the job with backoff (up to 5 attempts).
  Reconciliation is idempotent, so retries only re-attempt the
  still-failing pairs.

Caveats:

- The plan can go stale. If the world has changed between `plan/2`
  and `apply_plan!/3` (a member was added/removed, the role changed
  again, etc.), recompute or show a "preview is N seconds old" hint.
- The granter chain runs at apply time. If `:actor` was the strategy
  and the actor's session expired between preview and confirm, the
  apply may fall through to `:request`. Expect this: the plan shape
  is what's *about to happen*, but the strategy runs late.

## Pending grant requests

When the chain falls through to `:request`, a row in the configured
grant_requests_resource is created:
`(subject_id, target_principal_id, requested_by, requested_at,
fulfilled_at: nil)`.

Fulfill them whenever an actor with an existing grant comes online.
Three common patterns:

### Login-time fulfillment

Hook into your auth pipeline (or a Phoenix plug) to call
`fulfill_outstanding/5` on every authenticated request:

```elixir
defmodule MyAppWeb.Plugs.FulfillEvidenceRequests do
  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.assigns[:current_user] do
      nil ->
        conn

      actor ->
        actor = MyApp.Users.load_with_private_key(actor)
        _ = AshEnvelope.GrantRequests.fulfill_outstanding(
          @requests_config, @grants_config, actor, MyApp.Catalog,
          &load_target_user/1
        )
        conn
    end
  end

  defp load_target_user(user_id) do
    Ash.get(MyApp.User, user_id, authorize?: false, load: [:encryption_public_key])
  end
end
```

The function is cheap when there's nothing to do (one indexed read per
call, zero writes).

### Admin panel

List + fulfill on demand:

```elixir
def list_pending(actor) do
  AshEnvelope.GrantRequests.list_fulfillable_for(
    @requests_config, @grants_config, actor, MyApp.Catalog
  )
end

def approve(actor, request) do
  {:ok, target} = Ash.get(MyApp.User, request.user_id,
                          authorize?: false,
                          load: [:encryption_public_key])

  AshEnvelope.GrantRequests.fulfill(
    @requests_config, @grants_config, request, actor, target, MyApp.Catalog
  )
end
```

### Per-request hot path

If you want fulfillment at the moment someone tries to read a subject,
call `fulfill_outstanding/5` from your read-action preparation. Same
function — just a different trigger.

## Troubleshooting

- **`no_grant_requests_resource`** — `:request` is in the chain but
  `grant_requests_resource` isn't configured in the `reconcile do`
  block.
- **Grant never materializes** — the actor probably doesn't have their
  private key loaded. Set `user_load:` in `reconcile do` to point at
  your cloak calc so the actor's private key resolves before the chain
  runs, or load the key on the actor before triggering the action.
- **Pending requests never fulfill** — no logged-in user with a grant
  on the subject is hitting your fulfillment hook. This is the
  recovery path: an admin (or a holder of the offline backup key) has
  to come online and fulfill manually.
