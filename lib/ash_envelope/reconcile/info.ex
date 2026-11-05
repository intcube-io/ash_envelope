defmodule AshEnvelope.Reconcile.Info do
  @moduledoc "Introspection helpers for `AshEnvelope.Reconcile`"
  use Spark.InfoGenerator, extension: AshEnvelope.Reconcile, sections: [:reconcile]

  alias AshEnvelope.{GrantRequests, KeyGrants}
  alias AshEnvelope.Reconcile.{Affects, Context}

  @doc """
  Build a `Context.t()` for the resource at runtime.

  Reads the shared grants config from `reconcile do`. The required fields
  (`domain`, `key_grants_resource`, `actor_public_key_attribute`,
  `actor_private_key_attribute`) are enforced at compile time by
  `AshEnvelope.Reconcile.Transformers.ValidateConfig`.
  """
  @spec context(module()) :: {:ok, Context.t()} | {:error, term()}
  def context(resource) do
    {:ok,
     %Context{
       encrypted_resource: resource,
       user_resource: reconcile_user_resource!(resource),
       key_grants_config: key_grants_config(resource),
       grant_requests_config: grant_requests_config(resource),
       granter_chain: reconcile_granter_chain!(resource),
       domain: reconcile_domain!(resource),
       user_load: reconcile_user_load!(resource),
       subject_load: reconcile_subject_load!(resource),
       subject_id_for: reconcile_subject_id_for(resource) |> ok_or_nil()
     }}
  end

  @doc """
  Build a `GrantRequests.Config` from the resource's DSL, or `nil` if no
  requests resource is configured.
  """
  @spec grant_requests_config(module()) :: GrantRequests.Config.t() | nil
  def grant_requests_config(resource) do
    case ok_or_nil(reconcile_grant_requests_resource(resource)) do
      nil ->
        nil

      requests_resource ->
        %GrantRequests.Config{
          resource: requests_resource,
          subject_id_attribute: reconcile_grant_requests_subject_id_attribute!(resource),
          target_principal_id_attribute:
            reconcile_grant_requests_target_principal_id_attribute!(resource),
          authorize?: reconcile_grant_requests_authorize?(resource)
        }
    end
  end

  @doc """
  All `affects` entries declared on `resource`'s `reconcile do` block.

  Delegates to the entity accessor `Spark.InfoGenerator` writes for us.
  Returns `[]` when none are declared.
  """
  @spec affects(module()) :: [Affects.t()]
  def affects(resource), do: reconcile(resource)

  @doc """
  All `affects` entries on `encrypted_resource` that target
  `affecting_resource`. Multiple entries are allowed (e.g. one per
  action subset with a different scope).
  """
  @spec affects_for(module(), module()) :: [Affects.t()]
  def affects_for(encrypted_resource, affecting_resource) do
    encrypted_resource
    |> affects()
    |> Enum.filter(&(&1.resource == affecting_resource))
  end

  @doc """
  Pick the `affects` entry on `encrypted_resource` that targets
  `affecting_resource` and lists `action` in its `actions`. Returns `nil`
  when none match — used by `SyncPrincipal` to skip silently when the
  action falls outside the declared subset.
  """
  @spec affects_for_action(module(), module(), atom()) :: Affects.t() | nil
  def affects_for_action(encrypted_resource, affecting_resource, action)
      when is_atom(encrypted_resource) and is_atom(affecting_resource) and is_atom(action) do
    encrypted_resource
    |> affects_for(affecting_resource)
    |> Enum.find(fn %Affects{actions: actions} -> action in actions end)
  end

  defp key_grants_config(resource) do
    KeyGrants.Config.from_options(
      resource: reconcile_key_grants_resource!(resource),
      actor_public_key_attribute: reconcile_actor_public_key_attribute!(resource),
      actor_private_key_attribute: reconcile_actor_private_key_attribute!(resource),
      subject_id_attribute: ok_or_nil(reconcile_key_grants_subject_id_attribute(resource)),
      principal_id_attribute: ok_or_nil(reconcile_key_grants_principal_id_attribute(resource)),
      dek_attribute: ok_or_nil(reconcile_key_grants_dek_attribute(resource)),
      expires_at_attribute: ok_or_nil(reconcile_key_grants_expires_at_attribute(resource)),
      authorize?: reconcile_key_grants_authorize?(resource)
    )
  end

  # Coerce a Spark accessor result (`{:ok, value}` or `:error`) to a plain
  # value or `nil`.
  defp ok_or_nil({:ok, value}), do: value
  defp ok_or_nil(:error), do: nil
end
