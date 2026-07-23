defmodule AshEnvelope.Reconcile.Changes.SyncSubject do
  @moduledoc """
  Ash resource change to install on the **encrypted resource itself**,
  so that creating or updating a subject (typically the moment a fresh
  blob lands and the uploader's grant is auto-created) fans grants out
  to every other authorized user.

  Walks `candidates` (or, by default, every record of `:user_resource`)
  and reconciles each `(candidate, this_subject)` pair via
  `AshEnvelope.Reconcile.Runner`. The runner uses `Ash.can?(:read, …)`
  as the truth, so an unauthorized candidate becomes a no-op.

  ## Options

  - `:candidates` *(optional)* — `(Ash.Resource.record() -> Ash.Query.t())`
    returning a narrowed candidate user query. Defaults to the
    user_resource configured on the resource's `reconcile do` block,
    unfiltered.

  ## Example

      update :update do
        change AshEnvelope.Reconcile.Changes.SyncSubject

        # or with a narrower candidate set:
        change {AshEnvelope.Reconcile.Changes.SyncSubject,
                candidates: fn _subject ->
                  Ash.Query.filter(MyApp.User, role in [:admin, :user])
                end}
      end
  """
  use Ash.Resource.Change

  alias AshEnvelope.Reconcile.{Info, Runner}

  require Ash.Query
  require Logger

  @impl true
  def init(opts), do: {:ok, opts}

  @impl true
  def change(changeset, opts, _context) do
    Ash.Changeset.after_transaction(changeset, fn cs, result ->
      case result do
        {:ok, subject} ->
          run(subject, cs, opts, result)

        _ ->
          result
      end
    end)
  end

  # SyncSubject always runs inline regardless of the resource's
  # `mode :async` setting: the freshly-generated DEK lives in the
  # current process dictionary (stashed by the encryption pipeline)
  # and would not survive a hop to an Oban worker. The chain's
  # `when:` filters still gate which strategies fire — non-self /
  # non-backup candidates fall through to `:request` here just as
  # they would in an async worker, so the end state matches.
  defp run(subject, cs, opts, result) do
    {:ok, ctx} = Info.context(subject.__struct__)
    ctx = %{ctx | actor: cs.context[:private][:actor], changeset: cs}

    case candidates(ctx, subject, opts) do
      {:ok, candidate_ids} ->
        pairs = Enum.map(candidate_ids, &{&1, subject})
        Runner.run(ctx, pairs)
        result

      {:error, reason} ->
        Logger.warning(
          "[AshEnvelope.Reconcile.SyncSubject] candidate enumeration failed: #{inspect(reason)}"
        )

        result
    end
  end

  defp candidates(ctx, subject, opts) do
    query =
      case Keyword.get(opts, :candidates) do
        nil -> ctx.user_resource
        fun when is_function(fun, 1) -> fun.(subject)
      end

    max = Application.get_env(:ash_envelope, :reconcile_max_subjects, 100_000)

    try do
      list =
        query
        |> Ash.stream!(domain: ctx.domain, authorize?: false, batch_size: 500)
        |> Enum.take(max + 1)

      if length(list) > max do
        {:error, {:candidate_set_too_large, max}}
      else
        {:ok, Enum.map(list, & &1.id)}
      end
    rescue
      e -> {:error, e}
    end
  end
end
