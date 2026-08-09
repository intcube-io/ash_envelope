defmodule AshEnvelope.Reconcile.Affecting.Transformers.InjectSyncPrincipal do
  @moduledoc """
  For each `encrypts` entry declared via `AshEnvelope.Reconcile.Affecting`:

  1. Inject a resource-level
     `change {SyncPrincipal, encrypted_resource: M}` filtered by the
     entry's `on:` action types. Resource-level changes apply to every
     matching action automatically, so users don't repeat the wire-up.
  2. Flip `require_atomic?` to `false` on `update`/`destroy` actions
     whose type appears in any `on:` list, since `SyncPrincipal` runs
     in `after_transaction` and is not atomic-safe.

  The change itself no-ops at runtime when the encrypted resource's
  matching `affects` entry doesn't list the executing action by name —
  the encrypted side remains the single source of truth.
  """
  use Spark.Dsl.Transformer

  alias AshEnvelope.Reconcile.Affecting.Encrypts
  alias AshEnvelope.Reconcile.Changes.SyncPrincipal
  alias Spark.Dsl.Transformer

  # Run after Ash expands `defaults [...]` into concrete action entities
  # — otherwise we'd miss those when flipping `require_atomic?`.
  @impl true
  def after?(Ash.Resource.Transformers.SetPrimaryActions), do: true
  def after?(_), do: false

  @impl true
  def transform(dsl_state) do
    entries = Transformer.get_entities(dsl_state, [:reconcile_affecting])

    Enum.reduce_while(entries, {:ok, dsl_state}, fn entry, {:ok, dsl_state} ->
      case process_entry(dsl_state, entry) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp process_entry(dsl_state, %Encrypts{resource: encrypted, on: types}) do
    with {:ok, dsl_state} <- relax_atomicity(dsl_state, types) do
      Ash.Resource.Builder.add_change(
        dsl_state,
        {SyncPrincipal, encrypted_resource: encrypted},
        on: types
      )
    end
  end

  defp relax_atomicity(dsl_state, types) do
    needs_relax =
      types
      |> Enum.filter(&(&1 in [:update, :destroy]))
      |> MapSet.new()

    if MapSet.size(needs_relax) == 0 do
      {:ok, dsl_state}
    else
      dsl_state
      |> Transformer.get_entities([:actions])
      |> Enum.filter(&MapSet.member?(needs_relax, Map.get(&1, :type)))
      |> Enum.reduce({:ok, dsl_state}, fn action, {:ok, dsl_state} ->
        relax_action(dsl_state, action)
      end)
    end
  end

  defp relax_action(dsl_state, action) do
    if Map.get(action, :require_atomic?, false) do
      relaxed = %{action | require_atomic?: false}
      action_name = action.name
      action_type = action.type

      {:ok,
       Transformer.replace_entity(dsl_state, [:actions], relaxed, fn entity ->
         Map.get(entity, :name) == action_name and Map.get(entity, :type) == action_type
       end)}
    else
      {:ok, dsl_state}
    end
  end
end
