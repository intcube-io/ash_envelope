defmodule AshEnvelope.Reconcile.Transformers.ValidateConfig do
  @moduledoc """
  Compile-time validation for `AshEnvelope.Reconcile`.

  Ensures the fields required to talk to the grants table are set in
  `reconcile do`:

      domain
      key_grants_resource
      actor_public_key_attribute
      actor_private_key_attribute

  Also validates:

  - every `granter_chain` entry is a known strategy shape (see
    `AshEnvelope.Reconcile.Granter`);
  - `grant_requests_resource` is set whenever `:request` appears in the
    effective chain — note the *default* chain is `[:actor, :request]`;
  - `mode :async` is only configured when Oban is compiled.
  """
  use Spark.Dsl.Transformer

  alias Spark.Dsl.Transformer

  @required ~w(
    domain
    key_grants_resource
    actor_public_key_attribute
    actor_private_key_attribute
  )a

  # Strategy shapes accepted by `AshEnvelope.Reconcile.Granter`.
  @bare_strategies [:actor, :request]
  @tuple_strategies [:actor, :request, :dek_from_process]

  # Spark applies schema defaults before transformers run; these mirror
  # the schema in `AshEnvelope.Reconcile` purely as a safety net.
  @default_chain [:actor, :request]

  @impl true
  def transform(dsl_state) do
    resource = Transformer.get_persisted(dsl_state, :module)
    chain = Transformer.get_option(dsl_state, [:reconcile], :granter_chain, @default_chain)

    with :ok <- validate_required(dsl_state, resource),
         :ok <- validate_chain_shapes(chain, resource),
         :ok <- validate_request_strategy(dsl_state, chain, resource),
         :ok <- validate_async_mode(dsl_state, resource) do
      {:ok, dsl_state}
    end
  end

  defp validate_required(dsl_state, resource) do
    case Enum.reject(@required, &explicitly_set?(dsl_state, &1)) do
      [] ->
        :ok

      missing ->
        error(resource, """
        #{inspect(resource)} uses `AshEnvelope.Reconcile` but `reconcile do` is missing required \
        field(s):

            #{Enum.map_join(missing, "\n    ", &to_string/1)}
        """)
    end
  end

  defp validate_chain_shapes(chain, resource) do
    case Enum.reject(chain, &valid_strategy?/1) do
      [] ->
        :ok

      invalid ->
        error(resource, """
        `granter_chain` on #{inspect(resource)} contains unknown strategy shape(s):

            #{Enum.map_join(invalid, "\n    ", &inspect/1)}

        Valid shapes are `:actor`, `:request`, `{:actor, opts}`, `{:request, opts}`, and \
        `{:dek_from_process, opts}`. See `AshEnvelope.Reconcile.Granter`.
        """)
    end
  end

  defp valid_strategy?(strategy) when strategy in @bare_strategies, do: true

  defp valid_strategy?({name, opts}) when name in @tuple_strategies and is_list(opts),
    do: Keyword.keyword?(opts)

  defp valid_strategy?(_), do: false

  defp validate_request_strategy(dsl_state, chain, resource) do
    request? =
      Enum.any?(chain, fn
        :request -> true
        {:request, _} -> true
        _ -> false
      end)

    if request? and not explicitly_set?(dsl_state, :grant_requests_resource) do
      error(resource, """
      `granter_chain` on #{inspect(resource)} includes `:request` (note: the default chain is \
      `[:actor, :request]`) but `reconcile do` does not set `grant_requests_resource`.

      Either set `grant_requests_resource` or drop `:request` from the chain, e.g.

          granter_chain [:actor]
      """)
    else
      :ok
    end
  end

  defp validate_async_mode(dsl_state, resource) do
    mode = Transformer.get_option(dsl_state, [:reconcile], :mode, :sync)

    if mode == :async and not Code.ensure_loaded?(Oban) do
      error(resource, """
      `reconcile do mode :async end` on #{inspect(resource)} requires Oban.

      Add `{:oban, "~> 2.18"}` to your mix.exs and configure a queue, or switch to `mode :sync`.
      """)
    else
      :ok
    end
  end

  defp error(resource, message) do
    {:error,
     Spark.Error.DslError.exception(
       module: resource,
       path: [:reconcile],
       message: message
     )}
  end

  defp explicitly_set?(dsl_state, field) do
    match?({:ok, _}, Transformer.fetch_option(dsl_state, [:reconcile], field))
  end
end
