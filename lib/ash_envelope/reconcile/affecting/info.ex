defmodule AshEnvelope.Reconcile.Affecting.Info do
  @moduledoc "Introspection helpers for `AshEnvelope.Reconcile.Affecting`."

  use Spark.InfoGenerator,
    extension: AshEnvelope.Reconcile.Affecting,
    sections: [:reconcile_affecting]

  alias AshEnvelope.Reconcile.Affecting.Encrypts

  @doc "All `encrypts` entries declared on `resource`."
  @spec encrypts(module()) :: [Encrypts.t()]
  def encrypts(resource), do: reconcile_affecting(resource)
end
