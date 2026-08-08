defmodule AshEnvelope.Test.Reconcile.FailGrantDestroy do
  @moduledoc false

  # Failure injection for the reconcile error-surfacing tests: when the
  # calling process sets the `:ash_envelope_fail_grant_destroy` pdict
  # flag, the destroy action errors. Everything runs in the test process
  # (ETS data layer, in-line changes), so the flag scopes the fault to a
  # single test even under `async: true`. Implements `atomic/3` so bulk
  # destroys (used by other tests for cleanup) keep working.

  use Ash.Resource.Change

  @impl true
  def change(changeset, _opts, _context) do
    if fail?() do
      Ash.Changeset.add_error(changeset, injected_error())
    else
      changeset
    end
  end

  @impl true
  def atomic(_changeset, _opts, _context) do
    if fail?() do
      {:error, injected_error()}
    else
      :ok
    end
  end

  defp fail?, do: Process.get(:ash_envelope_fail_grant_destroy) == true

  defp injected_error do
    Ash.Error.Changes.InvalidChanges.exception(
      fields: [:id],
      message: "injected grant destroy failure"
    )
  end
end
