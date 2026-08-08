defmodule AshEnvelope.Reconcile.Plan do
  @moduledoc """
  A computed reconciliation diff: the set of grant operations that
  `AshEnvelope.Reconcile.Runner.apply_plan!/2` will perform.

  Produced by `Runner.plan/2`. Useful when you want to surface "what's
  about to happen" to a user before any rows touch the grants table —
  call `plan/2` from a controller/LiveView, render it, then call
  `apply_plan!/3` on confirm.

  ## Fields

  - `:grants` — pairs that the read policy authorizes but currently have
    no grant. Each entry: `%{principal_id, subject, subject_id, target}`.
    `target` is the loaded principal struct (with the configured
    `user_load` applied), suitable for passing through the granter chain.
  - `:revocations` — pairs that have a grant but the read policy no
    longer authorizes. Each entry: `%{principal_id, subject_id}`.
  - `:errors` — `[{principal_id, reason}]` from pairs that errored out
    during planning (subject missing, principal missing, etc.).
    `Runner.apply_plan!/3` folds these into its return value as
    `:plan_errors`, so a plan that only carries errors still yields
    `{:error, aggregate}` at apply time.
  """

  defstruct grants: [],
            revocations: [],
            errors: []

  @type grant_entry :: %{
          principal_id: term(),
          subject: Ash.Resource.record(),
          subject_id: term(),
          target: term()
        }

  @type revocation_entry :: %{principal_id: term(), subject_id: term()}

  @type t :: %__MODULE__{
          grants: [grant_entry()],
          revocations: [revocation_entry()],
          errors: [{term(), term()}]
        }

  @doc "True iff this plan would not write or delete any rows."
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{grants: [], revocations: []}), do: true
  def empty?(%__MODULE__{}), do: false
end
