defmodule AshEnvelope.Reconcile.Affecting.Encrypts do
  @moduledoc """
  A single declarative `encrypts` entry on an affecting resource's
  `reconcile_affecting do … end` block.

  Captures the encrypted resource module and the action types whose
  lifecycle should fan out grants. Consumed by
  `AshEnvelope.Reconcile.Affecting.Transformers.InjectSyncPrincipal`,
  which expands each entry into a resource-level
  `change AshEnvelope.Reconcile.Changes.SyncPrincipal` so callers
  don't have to wire up the change per-action.
  """

  defstruct [:resource, on: [:create, :update, :destroy], __spark_metadata__: nil]

  @type t :: %__MODULE__{
          resource: module(),
          on: [atom()]
        }
end
