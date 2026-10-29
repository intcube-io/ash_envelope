defmodule AshEnvelope.Reconcile do
  @moduledoc """
  Spark extension that supplies the configuration needed to keep an
  encrypted resource's `KeyGrants` table in sync with its `:read` policy.

  The host installs two stock change modules — `SyncSubject` on the
  encrypted resource and `SyncPrincipal` on each "affecting" resource
  whose lifecycle changes read authorization (memberships, role
  attributes, etc.). Both feed into `AshEnvelope.Reconcile.Runner`,
  which walks the configured `granter_chain` and reconciles grants
  against `Ash.can?(:read, subject, actor: principal)`.

  ## DSL

      reconcile do
        user_resource MyApp.User                              # required
        domain MyApp.Storage                                  # required
        key_grants_resource MyApp.DocumentKeyGrant            # required
        actor_public_key_attribute :public_key                # required
        actor_private_key_attribute :private_key              # required
        grant_requests_resource MyApp.DocumentGrantRequest    # required iff `:request` in chain
        granter_chain [:actor, :request]                      # default
        user_load [:encryption_private_key]                   # cloak load list

        # One entry per "affecting" resource. SyncPrincipal looks these
        # up to drop the per-action principal/scope/only_when boilerplate.
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

  ## Wiring the change modules

  Encrypted resource — runs reconciliation when a new subject is created
  or its blob is rotated:

      update :update do
        change AshEnvelope.Reconcile.Changes.SyncSubject
      end

  Affecting resource — one-line wire-up that looks up the matching
  `affects` entry on the encrypted resource:

      update :update do
        accept [:role]
        change {AshEnvelope.Reconcile.Changes.SyncPrincipal,
                encrypted_resource: MyApp.Document}
      end

  The change resolves principal/scope/only_when at runtime from the
  encrypted resource's `affects __MODULE__` entry whose `actions` list
  includes the current action. The explicit form (passing
  `principal:`/`scope:`/`only_when:` directly) still works and overrides
  the lookup.

  ## Granter chain

  See `AshEnvelope.Reconcile.Granter` for the strategy semantics:

  - `{:dek_from_process, key_for: fun}` — bootstrap a grant from a
    freshly-generated DEK stashed in the process dictionary by the
    encryption pipeline.
  - `:actor` — the actor of the triggering changeset re-wraps the DEK
    (must hold a grant on the subject and have a usable private key).
  - `:request` — write a pending row to `grant_requests_resource`,
    fulfilled later by an authorized user.

  ## Failure surfacing

  `Runner.run/3` and `Runner.apply_plan!/3` return `:ok` only when
  every planned grant/revocation applied cleanly; otherwise they return
  `{:error, aggregate}` where `aggregate` collects `:grant_failures`,
  `:revoke_failures`, and `:plan_errors` (see
  `t:AshEnvelope.Reconcile.Runner.apply_error/0`). How that surfaces
  depends on the mode:

  - **`:sync`** — the change modules run reconciliation in
    `after_transaction`, *after* the host write has committed, so a
    reconcile failure never turns the successful write into an error.
    The aggregate is logged at `:warning` and the original result is
    returned. Call `Runner.run/3` directly when you need to react to
    the return value programmatically.
  - **`:async`** — `AsyncWorker.perform/1` returns the aggregate to
    Oban, which retries the job with backoff (up to 5 attempts).
    Reconciliation is idempotent, so each retry only re-attempts the
    still-failing pairs.

  ## Multitenancy

  The change modules capture the triggering changeset's tenant into
  `AshEnvelope.Reconcile.Context` and thread it through everything the
  reconcile subsystem does: subject/candidate enumeration streams, the
  `Ash.can?` authorization check, and every read/write against the
  user, encrypted, grants, and grant-requests resources. `scope :all`
  and `SyncSubject`'s candidate set therefore fan out only within the
  triggering tenant. In `:async` mode the tenant rides in the Oban job
  args (serialized via `Ash.ToTenant.to_tenant/2`) and is restored by
  `AshEnvelope.Reconcile.AsyncWorker` — context-multitenancy hosts must
  use a tenant value that survives a JSON round-trip (string/integer).
  A `nil` tenant (single-tenant hosts) behaves exactly as before.

  Future work (tracked in
  [the design proposal](../proposals/reconcile-and-grant-requests.md)):
  auto-derive an `affects` plan from the encrypted resource's read
  policy AST so neither the `change` lines nor any further config are
  needed in the common case.

  ## Required fields

  `domain`, `key_grants_resource`, `actor_public_key_attribute`, and
  `actor_private_key_attribute` are required and must be set in
  `reconcile do`. `grant_requests_resource` is additionally required
  whenever `:request` appears in the effective `granter_chain` — and the
  *default* chain is `[:actor, :request]`, so a minimal config must
  either set it or narrow the chain (e.g. `granter_chain [:actor]`).
  Compile-time validation (including granter-chain entry shapes and the
  Oban dependency for `mode :async`) is performed by
  `AshEnvelope.Reconcile.Transformers.ValidateConfig`.

  When the encrypted resource is an `AshStorage` attachment using
  `AshStorage.Layer.Encryption` with the
  `AshEnvelope.BlobIO.KeyManagers.KeyGrants` key manager, the same
  grants resource is configured on both sides. Keep the values in
  `reconcile do` and the key-manager opts in sync — they read and write
  the same table.
  """

  @affects %Spark.Dsl.Entity{
    name: :affects,
    describe:
      "Declares an affecting resource — one whose lifecycle changes who is authorized to read the encrypted resource. Looked up by `AshEnvelope.Reconcile.Changes.SyncPrincipal` to drop per-action principal/scope/only_when boilerplate.",
    target: AshEnvelope.Reconcile.Affects,
    args: [:resource],
    schema: [
      resource: [
        type: :atom,
        required: true,
        doc: "The Ash resource module whose actions affect read authorization."
      ],
      actions: [
        type: {:list, :atom},
        default: [:create, :update, :destroy],
        doc:
          "Actions on the affecting resource that should fire reconciliation. Defaults to all mutating action types."
      ],
      principal: [
        type: :atom,
        required: true,
        doc:
          "Attribute on the affecting resource pointing at the user/principal whose authorization may have changed (e.g. `:user_id` on a membership, `:id` on the user resource itself)."
      ],
      scope: [
        type: {:or, [{:in, [:all]}, {:fun, 1}]},
        required: true,
        doc:
          "Either `:all` (every encrypted record) or a `(Ash.Changeset.t() -> Ash.Query.t() | keyword() | [term()])` filter. The function receives the changeset and must return an `Ash.Query`, a keyword filter, or a list of subject ids."
      ],
      only_when: [
        type: {:fun, 1},
        required: false,
        doc:
          "Optional `(Ash.Changeset.t() -> boolean())`. When it returns `false`, reconciliation is skipped for that change. Useful for `User.update` actions that only matter when a specific attribute moves."
      ]
    ]
  }

  @reconcile %Spark.Dsl.Section{
    name: :reconcile,
    describe:
      "Configuration for grant reconciliation against the encrypted resource's read policy.",
    entities: [@affects],
    schema: [
      user_resource: [
        type: :atom,
        required: true,
        doc: "The user/principal resource module. Used to load actors and their key material."
      ],
      domain: [
        type: :atom,
        required: false,
        doc: "Ash domain for grant operations."
      ],
      key_grants_resource: [
        type: :atom,
        required: false,
        doc: "Ash resource backing the `KeyGrants` table."
      ],
      key_grants_subject_id_attribute: [
        type: :atom,
        required: false,
        doc:
          "FK attribute on the grants resource pointing at the subject. Defaults to `:blob_id`."
      ],
      key_grants_principal_id_attribute: [
        type: :atom,
        required: false,
        doc:
          "FK attribute on the grants resource pointing at the principal. Defaults to `:user_id`."
      ],
      key_grants_dek_attribute: [
        type: :atom,
        required: false,
        doc:
          "Attribute on the grants resource holding the wrapped DEK. Defaults to `:wrapped_dek`."
      ],
      key_grants_expires_at_attribute: [
        type: :atom,
        required: false,
        doc:
          "Nullable `utc_datetime_usec` attribute on the grants resource marking grant expiry. When set, the planner treats expired rows as absent, so reconcile destroys and re-issues them while the read policy still authorizes the principal. Defaults to `nil` (expiry disabled)."
      ],
      actor_public_key_attribute: [
        type: :atom,
        required: false,
        doc: "Attribute on the actor holding their X25519 public key."
      ],
      actor_private_key_attribute: [
        type: :atom,
        required: false,
        doc: "Attribute on the actor holding their X25519 private key."
      ],
      grant_requests_resource: [
        type: :atom,
        required: false,
        doc:
          "Ash resource for pending grant requests. Required when `:request` appears in `granter_chain`."
      ],
      grant_requests_subject_id_attribute: [
        type: :atom,
        default: :blob_id,
        doc: "FK attribute on the grant requests resource pointing at the subject."
      ],
      grant_requests_target_principal_id_attribute: [
        type: :atom,
        default: :user_id,
        doc: "FK attribute on the grant requests resource pointing at the target principal."
      ],
      grant_requests_authorize?: [
        type: :boolean,
        default: true,
        doc:
          "Whether Ash policy authorization is applied to grant request operations during reconciliation. Set to `false` when the grant requests resource enforces server-side-only creation via policies."
      ],
      key_grants_authorize?: [
        type: :boolean,
        default: true,
        doc:
          "Whether Ash policy authorization is applied to key grant operations during reconciliation. Set to `false` when the key grants resource enforces server-side-only creation via policies."
      ],
      granter_chain: [
        type: {:list, :any},
        default: [:actor, :request],
        doc: "Ordered list of granter strategies. See `AshEnvelope.Reconcile.Granter`."
      ],
      user_load: [
        type: {:list, :any},
        default: [],
        doc:
          "Loads to apply when fetching user records. Typically `[:private_key_calc]` so a cloak-decrypt calc resolves."
      ],
      subject_id_for: [
        type: {:fun, 1},
        required: false,
        doc:
          "Optional `(record -> id | nil)` callback that returns the id used in the grants table for a given encrypted resource record. Defaults to `& &1.id`. Override when grants are keyed by a related row's id (e.g. an attachment blob)."
      ],
      subject_load: [
        type: {:list, :any},
        default: [],
        doc:
          "Loads to apply when fetching the encrypted resource. Use this when `subject_id_for` needs to walk relations (e.g. `[file: [:blob]]`)."
      ],
      mode: [
        type: {:in, [:sync, :async]},
        default: :sync,
        doc:
          "`:sync` (default) — change modules apply reconciliation in `after_transaction`. `:async` — `SyncPrincipal` resolves the scope inline (cheap SELECT) and inserts an Oban job carrying subject ids + principal id + actor id (no key material) in `after_action`, inside the triggering transaction, so the job commits atomically with the write and the rewrap work happens off-request. Requires `:oban` to be available. May also be overridden per change via the `mode:` option."
      ],
      oban_queue: [
        type: :atom,
        default: :ash_envelope_reconcile,
        doc:
          "Oban queue used for `:async` mode jobs. Default `:ash_envelope_reconcile`. The host is responsible for declaring this queue in their Oban config."
      ],
      oban_chunk_size: [
        type: :pos_integer,
        default: 5000,
        doc:
          "When `:async` mode resolves a scope to more than this many subject ids, the trigger splits them across multiple Oban jobs. Default 5000."
      ],
      oban_name: [
        type: :atom,
        default: Oban,
        doc:
          "Name of the Oban instance `:async` mode jobs are inserted into (first argument to `Oban.insert!/2`). Default `Oban`. Set this when the host supervises Oban under a custom name."
      ]
    ]
  }

  use Spark.Dsl.Extension,
    sections: [@reconcile],
    transformers: [AshEnvelope.Reconcile.Transformers.ValidateConfig]
end
