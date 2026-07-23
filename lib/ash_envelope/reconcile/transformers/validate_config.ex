defmodule AshEnvelope.Reconcile.Transformers.ValidateConfig do
  @moduledoc """
  Compile-time validation for `AshEnvelope.Reconcile`.

  Ensures the fields required to talk to the grants table are set in
  `reconcile do`:

      domain
      key_grants_resource
      actor_public_key_attribute
      actor_private_key_attribute
  """
  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  @required ~w(
    domain
    key_grants_resource
    actor_public_key_attribute
    actor_private_key_attribute
  )a

  @impl true
  def transform(dsl_state) do
    resource = Transformer.get_persisted(dsl_state, :module)

    case Enum.reject(@required, &explicitly_set?(dsl_state, &1)) do
      [] ->
        {:ok, dsl_state}

      missing ->
        {:error,
         Spark.Error.DslError.exception(
           module: resource,
           path: [:reconcile],
           message: """
           #{inspect(resource)} uses `AshEnvelope.Reconcile` but `reconcile do` is missing required \
           field(s):

               #{Enum.map_join(missing, "\n    ", &to_string/1)}
           """
         )}
    end
  end

  defp explicitly_set?(dsl_state, field) do
    match?({:ok, _}, Transformer.fetch_option(dsl_state, [:reconcile], field))
  end
end
