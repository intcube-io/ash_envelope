defmodule AshEnvelope.Reconcile.Affects do
  @moduledoc """
  A single declarative `affects` entry on the encrypted resource's
  `reconcile do … end` block.

  Captures: the affecting resource, the actions whose lifecycle changes
  read authorization, the FK on the affecting resource that points to
  the user/principal, the scope used to enumerate subjects to reconcile
  against that principal, and an optional `only_when` predicate that
  short-circuits the reconcile when nothing relevant changed.

  Inspected at runtime via `AshEnvelope.Reconcile.Info.affects/1` and
  `affects_for/2`. Consumed by `AshEnvelope.Reconcile.Changes.SyncPrincipal`
  in its lookup form (`change {SyncPrincipal, encrypted_resource: …}`).
  """

  defstruct [
    :resource,
    :principal,
    :scope,
    :only_when,
    actions: [:create, :update, :destroy],
    __spark_metadata__: nil
  ]

  @type scope ::
          :all
          | (Ash.Changeset.t() -> Ash.Query.t() | keyword() | [term()])

  @type t :: %__MODULE__{
          resource: module(),
          actions: [atom()],
          principal: atom(),
          scope: scope(),
          only_when: (Ash.Changeset.t() -> boolean()) | nil
        }
end
