defmodule AshEnvelope.Reconcile.Affecting do
  @moduledoc """
  Spark extension installed on resources whose lifecycle changes affect
  read authorization for an encrypted resource (memberships, role
  attributes, etc.).

  Replaces per-action `change {SyncPrincipal, encrypted_resource: …}`
  boilerplate with a single resource-level declaration. The transformer
  injects `AshEnvelope.Reconcile.Changes.SyncPrincipal` once per
  `encrypts` entry, scoped via `on:` to action types. The change is a
  silent no-op when the action falls outside the encrypted resource's
  matching `affects` block, so over-injection is harmless — the
  encrypted resource's `reconcile do affects … end` declarations remain
  the single source of truth for which actions actually reconcile.

  ## DSL

      use Ash.Resource, extensions: [AshEnvelope.Reconcile.Affecting]

      reconcile_affecting do
        encrypts MyApp.Document
        encrypts MyApp.OtherEncrypted, on: [:create, :destroy]
      end

  ## Atomicity

  `SyncPrincipal` runs in `after_transaction`, which is incompatible
  with `require_atomic? true`. The transformer flips `require_atomic?`
  to `false` on every `update`/`destroy` action whose type appears in
  any `on:` list. Create actions are unaffected.

  ## Comparison with explicit wire-up

  Manual wire-up is still supported and useful when you need to
  override `principal` / `scope` / `only_when` per action, or when an
  action shouldn't share the resource-level default. See
  `AshEnvelope.Reconcile.Changes.SyncPrincipal`.
  """

  @encrypts %Spark.Dsl.Entity{
    name: :encrypts,
    describe:
      "Declare an encrypted resource whose grants should reconcile when this resource's actions fire. Expands into one resource-level `change SyncPrincipal` filtered by action type.",
    target: AshEnvelope.Reconcile.Affecting.Encrypts,
    args: [:resource],
    schema: [
      resource: [
        type: :atom,
        required: true,
        doc:
          "The encrypted resource module — i.e. one that declares `reconcile do affects __MODULE__ end`."
      ],
      on: [
        type: {:list, {:in, [:create, :update, :destroy]}},
        default: [:create, :update, :destroy],
        doc:
          "Action types on this resource that should fire reconciliation. Defaults to all mutating types. The change still no-ops when the action's name isn't in the encrypted resource's matching `affects` entry."
      ]
    ]
  }

  @section %Spark.Dsl.Section{
    name: :reconcile_affecting,
    describe:
      "Declare which encrypted resources this resource affects. Replaces per-action `change SyncPrincipal` wire-up.",
    entities: [@encrypts]
  }

  use Spark.Dsl.Extension,
    sections: [@section],
    transformers: [AshEnvelope.Reconcile.Affecting.Transformers.InjectSyncPrincipal]
end
