defmodule AshEnvelope.Reconcile.Mode do
  @moduledoc """
  Helpers for resolving the `:sync` / `:async` mode in
  `AshEnvelope.Reconcile.Changes.SyncSubject` and
  `AshEnvelope.Reconcile.Changes.SyncPrincipal`.

  - `:sync` (default) — reconciliation runs in the triggering action's
    `after_transaction`, blocking the response until grants/requests
    are written.
  - `:async` — `SyncPrincipal` enumerates the scope synchronously
    (fast — one filtered SELECT) and enqueues an `Oban` job carrying
    the resolved subject ids, the principal id, and the actor id (no
    key material). The job re-loads the actor by id and runs the
    granter chain. Requires `:oban` to be available; the encrypted
    resource's `reconcile do oban_queue ... end` controls the queue.
  """

  alias AshEnvelope.Reconcile.Info

  @valid_modes [:sync, :async]

  @doc """
  Resolve mode from per-change `opts` first, then from the encrypted
  resource's `reconcile do mode end`. Defaults to `:sync`.
  """
  @spec resolve(keyword(), module()) :: :sync | :async
  def resolve(opts, encrypted_resource) do
    case Keyword.get(opts, :mode) do
      nil ->
        case Info.reconcile_mode(encrypted_resource) do
          {:ok, mode} when mode in @valid_modes -> mode
          _ -> :sync
        end

      mode when mode in @valid_modes ->
        mode
    end
  end
end
