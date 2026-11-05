defmodule AshEnvelope.Test.Reconcile.UnresolvableCheck do
  @moduledoc false

  # A manual policy check the authorizer cannot resolve at pre-flight:
  # `strict_check/3` always answers `:unknown` and there is no filter
  # form, so inside an `access_type :runtime` policy `Ash.can?/3` yields
  # `:maybe` (coerced by `maybe_is`) even with `run_queries?: true`. The
  # runtime `check/4` matches everything, so real reads still succeed.

  use Ash.Policy.Check

  @impl true
  def describe(_opts), do: "unresolvable at pre-flight"

  @impl true
  def strict_check(_actor, _authorizer, _opts), do: {:ok, :unknown}

  @impl true
  def check(_actor, records, _authorizer, _opts), do: records
end
