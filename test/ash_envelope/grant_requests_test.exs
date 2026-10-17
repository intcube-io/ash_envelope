defmodule AshEnvelope.GrantRequestsTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.{GrantRequests, KeyGrants}

  require Ash.Query

  @domain AshEnvelope.Test.Domain

  setup do
    {actor_pub, actor_priv} = AshEnvelope.generate_key_pair()
    {target_pub, target_priv} = AshEnvelope.generate_key_pair()

    actor = %{id: Ash.UUID.generate(), public_key: actor_pub, private_key: actor_priv}
    target = %{id: Ash.UUID.generate(), public_key: target_pub, private_key: target_priv}
    requester = %{id: Ash.UUID.generate()}

    requests_config = %GrantRequests.Config{
      resource: AshEnvelope.Test.GrantRequest,
      subject_id_attribute: :subject_id,
      target_principal_id_attribute: :user_id
    }

    grants_config = %KeyGrants.Config{
      resource: AshEnvelope.Test.Grant,
      subject_id_attribute: :subject_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
    }

    %{
      requests_config: requests_config,
      grants_config: grants_config,
      actor: actor,
      target: target,
      requester: requester,
      subject_id: Ash.UUID.generate(),
      dek: AshEnvelope.generate_dek()
    }
  end

  describe "create/5" do
    test "creates a pending request row", ctx do
      assert :ok =
               GrantRequests.create(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target,
                 ctx.requester,
                 @domain
               )

      assert {:ok, [row]} =
               GrantRequests.list_pending_for_subject(
                 ctx.requests_config,
                 ctx.subject_id,
                 @domain
               )

      assert row.user_id == ctx.target.id
      assert row.requested_by_id == ctx.requester.id
      assert row.requested_at
      assert is_nil(row.fulfilled_at)
    end

    test "is idempotent on (subject, target) when pending", ctx do
      assert :ok =
               GrantRequests.create(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target,
                 ctx.requester,
                 @domain
               )

      assert :ok =
               GrantRequests.create(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target,
                 ctx.requester,
                 @domain
               )

      {:ok, rows} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      assert length(rows) == 1
    end

    # SR15: idempotency must hold under repeated invocation. True
    # concurrency cannot be exercised against the ETS data layer (private
    # per-process tables, no atomic unique-constraint enforcement), so we
    # assert the serial repeat-invariant here and rely on Postgres
    # integration tests in downstream applications to cover the race-
    # recovery branch in `do_create/6`.
    test "is idempotent under repeated invocation (SR15)", ctx do
      results =
        for _ <- 1..20 do
          GrantRequests.create(
            ctx.requests_config,
            ctx.subject_id,
            ctx.target,
            ctx.requester,
            @domain
          )
        end

      assert Enum.all?(results, &(&1 == :ok))

      {:ok, rows} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      assert length(rows) == 1
    end

    test "accepts a nil requested_by", ctx do
      assert :ok =
               GrantRequests.create(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target,
                 nil,
                 @domain
               )

      {:ok, [row]} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      assert is_nil(row.requested_by_id)
    end

    test "accepts an optional reason", ctx do
      assert :ok =
               GrantRequests.create(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target,
                 ctx.requester,
                 @domain,
                 reason: "added to org X"
               )

      {:ok, [row]} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      assert row.reason == "added to org X"
    end
  end

  describe "list_fulfillable_for/4" do
    test "filters to subjects the actor has a grant on", ctx do
      # Actor holds a grant on ctx.subject_id.
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      # Two pending requests: one on a subject the actor can fulfill, one not.
      other_subject = Ash.UUID.generate()

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.target,
          ctx.requester,
          @domain
        )

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          other_subject,
          ctx.target,
          ctx.requester,
          @domain
        )

      {:ok, fulfillable} =
        GrantRequests.list_fulfillable_for(
          ctx.requests_config,
          ctx.grants_config,
          ctx.actor,
          @domain
        )

      assert length(fulfillable) == 1
      assert hd(fulfillable).subject_id == ctx.subject_id
    end

    test "does not surface requests where actor IS the target", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      # Request targeting the actor themselves — actor can't fulfill for themselves.
      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.actor,
          ctx.requester,
          @domain
        )

      {:ok, fulfillable} =
        GrantRequests.list_fulfillable_for(
          ctx.requests_config,
          ctx.grants_config,
          ctx.actor,
          @domain
        )

      assert fulfillable == []
    end
  end

  describe "fulfill/6" do
    test "shares DEK and marks request fulfilled", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.target,
          ctx.requester,
          @domain
        )

      {:ok, [request]} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      assert :ok =
               GrantRequests.fulfill(
                 ctx.requests_config,
                 ctx.grants_config,
                 request,
                 ctx.actor,
                 ctx.target,
                 @domain
               )

      # Target can now resolve the DEK.
      {:ok, target_dek} =
        KeyGrants.resolve_for_actor(ctx.grants_config, ctx.subject_id, ctx.target, @domain)

      assert target_dek == ctx.dek

      # Request row is no longer pending.
      {:ok, pending} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      assert pending == []
    end

    test "is a no-op on already-fulfilled rows", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.target,
          ctx.requester,
          @domain
        )

      {:ok, [request]} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      :ok =
        GrantRequests.fulfill(
          ctx.requests_config,
          ctx.grants_config,
          request,
          ctx.actor,
          ctx.target,
          @domain
        )

      # Reload the now-fulfilled row.
      fulfilled =
        Ash.get!(AshEnvelope.Test.GrantRequest, request.id, domain: @domain, authorize?: false)

      # Calling fulfill again is a no-op (returns :ok without further side effects).
      assert :ok =
               GrantRequests.fulfill(
                 ctx.requests_config,
                 ctx.grants_config,
                 fulfilled,
                 ctx.actor,
                 ctx.target,
                 @domain
               )
    end
  end

  describe "fulfill_outstanding/5" do
    test "fulfills every request the actor can fulfill, returns counts", ctx do
      # Two subjects the actor holds a grant on, plus one pending request on each.
      subject_a = Ash.UUID.generate()
      subject_b = Ash.UUID.generate()
      dek_a = AshEnvelope.generate_dek()
      dek_b = AshEnvelope.generate_dek()

      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, subject_a, dek_a, ctx.actor, @domain)

      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, subject_b, dek_b, ctx.actor, @domain)

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          subject_a,
          ctx.target,
          ctx.requester,
          @domain
        )

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          subject_b,
          ctx.target,
          ctx.requester,
          @domain
        )

      target = ctx.target
      target_loader = fn _id -> {:ok, target} end

      assert {2, 0} =
               GrantRequests.fulfill_outstanding(
                 ctx.requests_config,
                 ctx.grants_config,
                 ctx.actor,
                 @domain,
                 target_loader
               )

      # Both targets resolve.
      {:ok, ^dek_a} =
        KeyGrants.resolve_for_actor(ctx.grants_config, subject_a, ctx.target, @domain)

      {:ok, ^dek_b} =
        KeyGrants.resolve_for_actor(ctx.grants_config, subject_b, ctx.target, @domain)
    end

    test "counts target-load failures as errors", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.target,
          ctx.requester,
          @domain
        )

      target_loader = fn _id -> {:error, :not_found} end

      assert {0, 1} =
               GrantRequests.fulfill_outstanding(
                 ctx.requests_config,
                 ctx.grants_config,
                 ctx.actor,
                 @domain,
                 target_loader
               )
    end

    test "counts a target without a public key as an error and keeps going", ctx do
      # A target that has not generated keys yet is a normal data
      # condition for a batch fulfiller, not a programmer error: it must
      # be counted, not abort the whole run.
      subject_a = Ash.UUID.generate()
      subject_b = Ash.UUID.generate()
      dek_a = AshEnvelope.generate_dek()
      dek_b = AshEnvelope.generate_dek()

      :ok = KeyGrants.create_for_actor(ctx.grants_config, subject_a, dek_a, ctx.actor, @domain)
      :ok = KeyGrants.create_for_actor(ctx.grants_config, subject_b, dek_b, ctx.actor, @domain)

      keyless = %{id: Ash.UUID.generate()}

      :ok = GrantRequests.create(ctx.requests_config, subject_a, keyless, ctx.requester, @domain)

      :ok =
        GrantRequests.create(ctx.requests_config, subject_b, ctx.target, ctx.requester, @domain)

      target = ctx.target

      target_loader = fn
        id when id == keyless.id -> {:ok, keyless}
        _ -> {:ok, target}
      end

      assert {1, 1} =
               GrantRequests.fulfill_outstanding(
                 ctx.requests_config,
                 ctx.grants_config,
                 ctx.actor,
                 @domain,
                 target_loader
               )

      # The keyed target was served despite the keyless one failing.
      {:ok, ^dek_b} =
        KeyGrants.resolve_for_actor(ctx.grants_config, subject_b, ctx.target, @domain)

      # The keyless target's request is still pending for a later run.
      {:ok, [pending]} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, subject_a, @domain)

      assert pending.user_id == keyless.id
    end
  end

  describe "revoke_pending_for/4" do
    test "drops unfulfilled rows for (subject, target)", ctx do
      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.target,
          ctx.requester,
          @domain
        )

      assert {:ok, 1} =
               GrantRequests.revoke_pending_for(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target.id,
                 @domain
               )

      {:ok, []} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)
    end

    test "leaves fulfilled rows untouched", ctx do
      :ok =
        KeyGrants.create_for_actor(ctx.grants_config, ctx.subject_id, ctx.dek, ctx.actor, @domain)

      :ok =
        GrantRequests.create(
          ctx.requests_config,
          ctx.subject_id,
          ctx.target,
          ctx.requester,
          @domain
        )

      {:ok, [request]} =
        GrantRequests.list_pending_for_subject(ctx.requests_config, ctx.subject_id, @domain)

      :ok =
        GrantRequests.fulfill(
          ctx.requests_config,
          ctx.grants_config,
          request,
          ctx.actor,
          ctx.target,
          @domain
        )

      assert {:ok, 0} =
               GrantRequests.revoke_pending_for(
                 ctx.requests_config,
                 ctx.subject_id,
                 ctx.target.id,
                 @domain
               )

      # The fulfilled row still exists.
      assert Ash.get!(AshEnvelope.Test.GrantRequest, request.id,
               domain: @domain,
               authorize?: false
             )
    end
  end
end
