defmodule AshEnvelope.GrantsPoliciesTest do
  # Exercises KeyGrants and GrantRequests against resources that carry
  # actor-scoped Ash policies (the shape scaffolded by the generators)
  # under the default `authorize?: true`. Before actors were threaded
  # into the Ash calls, every one of these flows either returned
  # :not_found or was forbidden, because policies were evaluated
  # against a nil actor.
  use ExUnit.Case, async: true

  alias AshEnvelope.{GrantRequests, KeyGrants}

  require Ash.Query

  @domain AshEnvelope.Test.Domain

  setup do
    {actor_pub, actor_priv} = AshEnvelope.generate_key_pair()
    {target_pub, target_priv} = AshEnvelope.generate_key_pair()

    actor = %{id: Ash.UUID.generate(), public_key: actor_pub, private_key: actor_priv}
    target = %{id: Ash.UUID.generate(), public_key: target_pub, private_key: target_priv}

    grants_config = %KeyGrants.Config{
      resource: AshEnvelope.Test.PoliciedGrant,
      subject_id_attribute: :subject_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
    }

    requests_config = %GrantRequests.Config{
      resource: AshEnvelope.Test.PoliciedGrantRequest,
      subject_id_attribute: :subject_id,
      target_principal_id_attribute: :user_id
    }

    %{
      grants_config: grants_config,
      requests_config: requests_config,
      actor: actor,
      target: target,
      subject_id: Ash.UUID.generate(),
      dek: AshEnvelope.generate_dek()
    }
  end

  describe "KeyGrants under authorize?: true with actor-scoped policies" do
    test "create_for_actor and resolve_for_actor round-trip", ctx do
      assert :ok =
               KeyGrants.create_for_actor(
                 ctx.grants_config,
                 ctx.subject_id,
                 ctx.dek,
                 ctx.actor,
                 @domain
               )

      assert {:ok, dek} =
               KeyGrants.resolve_for_actor(ctx.grants_config, ctx.subject_id, ctx.actor, @domain)

      assert dek == ctx.dek
    end

    test "read policy scopes resolve_for_actor to the actor's own grants", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      assert {:error, :not_found} =
               KeyGrants.resolve_for_actor(ctx.grants_config, ctx.subject_id, ctx.target, @domain)
    end

    test "share succeeds and is idempotent", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      assert :ok =
               KeyGrants.share(ctx.grants_config, ctx.subject_id, ctx.actor, ctx.target, @domain)

      assert :ok =
               KeyGrants.share(ctx.grants_config, ctx.subject_id, ctx.actor, ctx.target, @domain)

      assert {:ok, dek} =
               KeyGrants.resolve_for_actor(ctx.grants_config, ctx.subject_id, ctx.target, @domain)

      assert dek == ctx.dek

      subject = ctx.subject_id
      target_id = ctx.target.id

      {:ok, rows} =
        AshEnvelope.Test.PoliciedGrant
        |> Ash.Query.filter(subject_id == ^subject and user_id == ^target_id)
        |> Ash.read(domain: @domain, authorize?: false)

      assert length(rows) == 1
    end

    test "share re-issues past an expired row the read policy filters out", ctx do
      config = %{ctx.grants_config | expires_at_attribute: :expires_at}
      past = DateTime.add(DateTime.utc_now(), -60, :second)

      :ok = KeyGrants.create_for_actor(config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        KeyGrants.create_for_actor(
          config,
          ctx.subject_id,
          ctx.dek,
          ctx.target,
          @domain,
          expires_at: past
        )

      # The scaffolded read policy hides the expired row from the
      # target-side existence check; the expired row is purged
      # system-side and a fresh grant issued.
      assert :ok = KeyGrants.share(config, ctx.subject_id, ctx.actor, ctx.target, @domain)

      assert {:ok, dek} =
               KeyGrants.resolve_for_actor(config, ctx.subject_id, ctx.target, @domain)

      assert dek == ctx.dek

      subject = ctx.subject_id
      target_id = ctx.target.id

      {:ok, rows} =
        AshEnvelope.Test.PoliciedGrant
        |> Ash.Query.filter(subject_id == ^subject and user_id == ^target_id)
        |> Ash.read(domain: @domain, authorize?: false)

      assert length(rows) == 1
    end
  end

  describe "GrantRequests under authorize?: true with actor-scoped policies" do
    test "create and list_pending_for_subject work with the requester threaded", ctx do
      assert :ok =
               GrantRequests.create(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target,
                 ctx.actor,
                 @domain
               )

      assert {:ok, [row]} =
               GrantRequests.list_pending_for_subject(
                 ctx.requests_config,
                 ctx.subject_id,
                 @domain,
                 actor: ctx.actor
               )

      assert row.user_id == ctx.target.id
    end

    test "fulfill shares the DEK and marks the request fulfilled", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        GrantRequests.create(ctx.requests_config, ctx.subject_id, ctx.target, ctx.actor, @domain)

      {:ok, [request]} =
        GrantRequests.list_fulfillable_for(
          ctx.requests_config,
          ctx.grants_config,
          ctx.actor,
          @domain
        )

      assert :ok =
               GrantRequests.fulfill(
                 ctx.requests_config,
                 ctx.grants_config,
                 request,
                 ctx.actor,
                 ctx.target,
                 @domain
               )

      assert {:ok, dek} =
               KeyGrants.resolve_for_actor(ctx.grants_config, ctx.subject_id, ctx.target, @domain)

      assert dek == ctx.dek

      assert {:ok, []} =
               GrantRequests.list_pending_for_subject(
                 ctx.requests_config,
                 ctx.subject_id,
                 @domain,
                 actor: ctx.actor
               )
    end

    test "revoke_pending_for destroys rows visible to opts[:actor]", ctx do
      :ok =
        GrantRequests.create(ctx.requests_config, ctx.subject_id, ctx.target, ctx.actor, @domain)

      assert {:ok, 1} =
               GrantRequests.revoke_pending_for(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target.id,
                 @domain,
                 actor: ctx.actor
               )
    end
  end
end
