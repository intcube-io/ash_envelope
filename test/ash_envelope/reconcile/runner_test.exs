defmodule AshEnvelope.Reconcile.RunnerTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias AshEnvelope.{GrantRequests, KeyGrants}
  alias AshEnvelope.Reconcile.{Context, Runner}

  alias AshEnvelope.Test.Reconcile.{
    Document,
    Grant,
    GrantRequest,
    MaybeDocument,
    Membership,
    PoliciedGrant,
    PoliciedGrantRequest,
    User
  }

  require Ash.Query

  @domain AshEnvelope.Test.Reconcile.Domain

  defp make_user(role) do
    {pub, priv} = AshEnvelope.generate_key_pair()

    {:ok, user} =
      Ash.create(User, %{role: role, public_key: pub, private_key: priv}, domain: @domain)

    user
  end

  defp make_document do
    {:ok, doc} = Ash.create(Document, %{title: "doc-#{Ash.UUID.generate()}"}, domain: @domain)
    doc
  end

  defp make_membership(user, document) do
    {:ok, m} =
      Ash.create(Membership, %{user_id: user.id, document_id: document.id},
        domain: @domain,
        authorize?: false
      )

    m
  end

  defp grants_config do
    %KeyGrants.Config{
      resource: Grant,
      subject_id_attribute: :document_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
    }
  end

  defp requests_config do
    %GrantRequests.Config{
      resource: GrantRequest,
      subject_id_attribute: :document_id,
      target_principal_id_attribute: :user_id
    }
  end

  defp build_context(actor, opts \\ []) do
    %Context{
      encrypted_resource: Document,
      user_resource: User,
      key_grants_config: grants_config(),
      grant_requests_config: requests_config(),
      granter_chain: Keyword.get(opts, :granter_chain, [:actor, :request]),
      domain: @domain,
      actor: actor,
      user_load: []
    }
  end

  defp grant_for(user, document) do
    Grant
    |> Ash.Query.filter(document_id == ^document.id and user_id == ^user.id)
    |> Ash.read_one(domain: @domain, authorize?: false)
  end

  defp pending_request_for(user, document) do
    GrantRequest
    |> Ash.Query.filter(document_id == ^document.id and user_id == ^user.id)
    |> Ash.Query.filter(is_nil(fulfilled_at))
    |> Ash.read_one(domain: @domain, authorize?: false)
  end

  describe "should-grant transitions" do
    test ":actor strategy grants when actor holds the grant + key" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Actor uploaded the doc and holds the only grant.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      # Target becomes a member ⇒ should be granted.
      _ = make_membership(target, doc)

      ctx = build_context(actor)
      :ok = Runner.run(ctx, [{target.id, doc.id}])

      assert {:ok, %_{}} = grant_for(target, doc)

      # Target can resolve the same DEK.
      {:ok, target_dek} =
        KeyGrants.resolve_for_actor(grants_config(), doc.id, target, @domain)

      assert target_dek == dek
    end

    test ":actor falls through to :request when actor has no grant" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      ctx = build_context(actor)
      :ok = Runner.run(ctx, [{target.id, doc.id}])

      # No grant for the target — actor couldn't issue one.
      assert {:ok, nil} = grant_for(target, doc)
      # Pending request was created instead.
      assert {:ok, %_{}} = pending_request_for(target, doc)
    end

    # The actor holds a grant, but it was wrapped to a public key they no
    # longer own (keypair rotated afterwards). `:actor` used to surface
    # the resulting `:decryption_failed` as a terminal error, halting the
    # chain: the target ended up with neither a grant nor a pending
    # request, and in sync mode nothing ever retried.
    test ":actor whose key cannot open their grant falls through to :request" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      {new_pub, new_priv} = AshEnvelope.generate_key_pair()

      {:ok, actor} =
        Ash.update(actor, %{public_key: new_pub, private_key: new_priv},
          domain: @domain,
          authorize?: false
        )

      assert {:error, :decryption_failed} =
               KeyGrants.resolve_for_actor(grants_config(), doc.id, actor, @domain)

      ctx = build_context(actor)

      log = capture_log(fn -> assert :ok = Runner.run(ctx, [{target.id, doc.id}]) end)
      assert log =~ "cannot open its own grant"

      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, %_{}} = pending_request_for(target, doc)
    end

    test "actor IS the target — skips :actor and falls through to :request" do
      actor_target = make_user(:user)
      doc = make_document()
      _ = make_membership(actor_target, doc)

      ctx = build_context(actor_target)
      :ok = Runner.run(ctx, [{actor_target.id, doc.id}])

      # No grant created (you can't share to yourself).
      assert {:ok, nil} = grant_for(actor_target, doc)
      # Pending request queued.
      assert {:ok, %_{}} = pending_request_for(actor_target, doc)
    end

    test ":request strategy logs and skips when grant_requests_config is nil" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      ctx =
        build_context(actor)
        |> Map.put(:grant_requests_config, nil)

      log =
        capture_log(fn -> Runner.run(ctx, [{target.id, doc.id}]) end)

      assert log =~ "no_grant_requests_resource"
      assert {:ok, nil} = grant_for(target, doc)
    end
  end

  describe "should-NOT-grant transitions" do
    test "revokes existing grants when policy no longer authorizes" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      membership = make_membership(target, doc)

      # Seed: actor holds a grant; share to target so they have one too.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)
      :ok = KeyGrants.share(grants_config(), doc.id, actor, target, @domain)
      assert {:ok, %_{}} = grant_for(target, doc)

      # Target loses authorization (membership destroyed).
      :ok = Ash.destroy!(membership, domain: @domain, authorize?: false, return_destroyed?: false)

      ctx = build_context(actor)
      :ok = Runner.run(ctx, [{target.id, doc.id}])

      assert {:ok, nil} = grant_for(target, doc)
    end

    test "revoking also clears any pending grant request" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Pre-existing pending request for the target.
      :ok =
        GrantRequests.create(requests_config(), doc.id, target, actor, @domain)

      # No grant exists yet, but Ash.can? returns false (not a member, not admin)
      # — so the runner should clear the stale request.
      ctx = build_context(actor)

      # Seed an unauthorized grant directly to exercise the revoke path.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, target, @domain)

      :ok = Runner.run(ctx, [{target.id, doc.id}])

      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end
  end

  describe "no-op pairs" do
    test "authorized + already has grant → no work" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)
      :ok = KeyGrants.share(grants_config(), doc.id, actor, target, @domain)

      {:ok, before} = grant_for(target, doc)

      ctx = build_context(actor)
      :ok = Runner.run(ctx, [{target.id, doc.id}])

      {:ok, after_run} = grant_for(target, doc)
      assert before.id == after_run.id
      assert before.wrapped_dek == after_run.wrapped_dek
    end

    test "unauthorized + no grant → no work" do
      actor = make_user(:user)
      stranger = make_user(:user)
      doc = make_document()

      ctx = build_context(actor)
      :ok = Runner.run(ctx, [{stranger.id, doc.id}])

      assert {:ok, nil} = grant_for(stranger, doc)
      assert {:ok, nil} = pending_request_for(stranger, doc)
    end
  end

  describe "idempotency" do
    test "running twice produces the same DB state" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx = build_context(actor)
      :ok = Runner.run(ctx, [{target.id, doc.id}])
      {:ok, first} = grant_for(target, doc)

      :ok = Runner.run(ctx, [{target.id, doc.id}])
      {:ok, second} = grant_for(target, doc)

      assert first.id == second.id
      assert first.wrapped_dek == second.wrapped_dek
    end
  end

  # The planner's grants-table reads are bookkeeping, not the security
  # decision (`Ash.can?({subject, :read}, principal)` is). With an
  # actor-scoped policy on the grants resource and `authorize?: true`
  # config, the planner's nil-actor reads used to come back empty —
  # existing grants were invisible, so stale grants were never revoked.
  describe "policy-protected grants table" do
    defp policied_grants_config do
      %KeyGrants.Config{
        resource: PoliciedGrant,
        subject_id_attribute: :document_id,
        actor_public_key_attribute: :public_key,
        actor_private_key_attribute: :private_key,
        authorize?: true
      }
    end

    defp policied_requests_config do
      %GrantRequests.Config{
        resource: PoliciedGrantRequest,
        subject_id_attribute: :document_id,
        target_principal_id_attribute: :user_id,
        authorize?: true
      }
    end

    defp policied_context(actor) do
      %{
        build_context(actor)
        | key_grants_config: policied_grants_config(),
          grant_requests_config: policied_requests_config()
      }
    end

    defp policied_grant_for(user, document) do
      PoliciedGrant
      |> Ash.Query.filter(document_id == ^document.id and user_id == ^user.id)
      |> Ash.read_one(domain: @domain, authorize?: false)
    end

    test "plans and executes revocation of a stale grant under authorize?: true" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Seed a grant the read policy no longer authorizes (no membership),
      # plus a stale pending request. Seeding bypasses the table policies.
      dek = AshEnvelope.generate_dek()
      seed_config = %{policied_grants_config() | authorize?: false}
      :ok = KeyGrants.create_for_actor(seed_config, doc.id, dek, target, @domain)

      :ok =
        GrantRequests.create(
          %{policied_requests_config() | authorize?: false},
          doc.id,
          target,
          actor,
          @domain
        )

      ctx = policied_context(actor)

      plan = Runner.plan(ctx, [{target.id, doc.id}])
      assert [revocation] = plan.revocations
      assert revocation.principal_id == target.id
      assert revocation.subject_id == doc.id

      :ok = Runner.apply_plan!(ctx, plan)

      assert {:ok, nil} = policied_grant_for(target, doc)

      assert {:ok, nil} =
               PoliciedGrantRequest
               |> Ash.Query.filter(document_id == ^doc.id and user_id == ^target.id)
               |> Ash.Query.filter(is_nil(fulfilled_at))
               |> Ash.read_one(domain: @domain, authorize?: false)
    end

    test "detects an existing grant under authorize?: true — no duplicate issuance" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      seed_config = %{policied_grants_config() | authorize?: false}
      :ok = KeyGrants.create_for_actor(seed_config, doc.id, dek, target, @domain)

      ctx = policied_context(actor)

      plan = Runner.plan(ctx, [{target.id, doc.id}])
      assert AshEnvelope.Reconcile.Plan.empty?(plan)
    end
  end

  # `maybe_is: false` on the planner's `Ash.can?`: an unresolvable
  # `:maybe` policy result must never be treated as authorization to
  # issue a decryption grant.
  describe "unresolvable policy checks" do
    test "a :maybe read-policy result issues no grant and no request (fails closed)" do
      actor = make_user(:user)
      target = make_user(:user)

      {:ok, doc} =
        Ash.create(MaybeDocument, %{title: "maybe-doc"}, domain: @domain, authorize?: false)

      # Sanity: the policy genuinely resolves to :maybe for this pair even
      # with `run_queries?: true` — the default `maybe_is: true` would have
      # coerced this to "authorized" and issued a grant.
      assert {:ok, :maybe} = Ash.can({doc, :read}, target)
      assert Ash.can?({doc, :read}, target)
      refute Ash.can?({doc, :read}, target, maybe_is: false)

      # The actor could grant if the planner said yes.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx = %{build_context(actor) | encrypted_resource: MaybeDocument}

      plan = Runner.plan(ctx, [{target.id, doc.id}])
      assert AshEnvelope.Reconcile.Plan.empty?(plan)

      :ok = Runner.run(ctx, [{target.id, doc.id}])
      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end
  end

  # Expired rows count as absent for issuance (so reconcile re-issues per
  # the `KeyGrants` contract) and as present for revocation (stale rows
  # of unauthorized principals still get cleaned up).
  describe "expired grants" do
    defp expiring_grants_config do
      %{grants_config() | expires_at_attribute: :expires_at}
    end

    defp expiring_context(actor) do
      %{build_context(actor) | key_grants_config: expiring_grants_config()}
    end

    defp all_grants_for(user, document) do
      Grant
      |> Ash.Query.filter(document_id == ^document.id and user_id == ^user.id)
      |> Ash.read!(domain: @domain, authorize?: false)
    end

    defp past, do: DateTime.add(DateTime.utc_now(), -60, :second)
    defp future, do: DateTime.add(DateTime.utc_now(), 3600, :second)

    test "expired row + policy still authorizes → stale row destroyed, fresh grant issued" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      config = expiring_grants_config()
      :ok = KeyGrants.create_for_actor(config, doc.id, dek, actor, @domain)
      :ok = KeyGrants.create_for_actor(config, doc.id, dek, target, @domain, expires_at: past())

      [stale] = all_grants_for(target, doc)

      ctx = expiring_context(actor)

      plan = Runner.plan(ctx, [{target.id, doc.id}])
      assert [%{principal_id: principal_id}] = plan.grants
      assert principal_id == target.id
      assert plan.revocations == []

      :ok = Runner.apply_plan!(ctx, plan)

      # Exactly one row remains, and it's a fresh one — the stale row was
      # destroyed before issuance (a partial unique index on
      # (subject, principal) would otherwise collide).
      assert [fresh] = all_grants_for(target, doc)
      refute fresh.id == stale.id

      assert {:ok, resolved} = KeyGrants.resolve_for_actor(config, doc.id, target, @domain)
      assert resolved == dek
    end

    test "expired row + policy no longer authorizes → row revoked" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      config = expiring_grants_config()
      :ok = KeyGrants.create_for_actor(config, doc.id, dek, target, @domain, expires_at: past())

      ctx = expiring_context(actor)

      plan = Runner.plan(ctx, [{target.id, doc.id}])
      assert [%{principal_id: principal_id}] = plan.revocations
      assert principal_id == target.id
      assert plan.grants == []

      :ok = Runner.apply_plan!(ctx, plan)
      assert all_grants_for(target, doc) == []
    end

    test "unexpired row + policy authorizes → no-op" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      config = expiring_grants_config()

      :ok =
        KeyGrants.create_for_actor(config, doc.id, dek, target, @domain, expires_at: future())

      ctx = expiring_context(actor)
      plan = Runner.plan(ctx, [{target.id, doc.id}])

      assert AshEnvelope.Reconcile.Plan.empty?(plan)
    end
  end

  describe "plan/2" do
    alias AshEnvelope.Reconcile.Plan

    test "lists pairs that should-grant under :grants", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      reconcile_ctx = build_context(actor)
      plan = Runner.plan(reconcile_ctx, [{target.id, doc.id}])

      assert %Plan{grants: [grant], revocations: [], errors: []} = plan
      assert grant.principal_id == target.id
      assert grant.subject_id == doc.id
      assert grant.target.id == target.id
    end

    test "lists pairs that should-revoke under :revocations", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Grant exists but target has no membership → policy says no.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, target, @domain)

      reconcile_ctx = build_context(actor)
      plan = Runner.plan(reconcile_ctx, [{target.id, doc.id}])

      assert %Plan{grants: [], revocations: [revocation]} = plan
      assert revocation.principal_id == target.id
      assert revocation.subject_id == doc.id
    end

    test "no-op pairs produce an empty plan", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      reconcile_ctx = build_context(actor)
      plan = Runner.plan(reconcile_ctx, [{target.id, doc.id}])

      assert Plan.empty?(plan)
    end

    test "writes nothing — calling plan/2 doesn't touch the grants table", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      reconcile_ctx = build_context(actor)
      _plan = Runner.plan(reconcile_ctx, [{target.id, doc.id}])

      # No grant materialized.
      assert {:ok, nil} = grant_for(target, doc)
    end
  end

  describe "apply_plan!/3" do
    alias AshEnvelope.Reconcile.Plan

    test "executes the same writes as run/2", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      reconcile_ctx = build_context(actor)
      plan = Runner.plan(reconcile_ctx, [{target.id, doc.id}])
      :ok = Runner.apply_plan!(reconcile_ctx, plan)

      assert {:ok, %_{}} = grant_for(target, doc)
    end

    test "returns :ok on an empty plan without raising", ctx do
      reconcile_ctx = build_context(make_user(:user))
      assert :ok = Runner.apply_plan!(reconcile_ctx, %Plan{})
    end

    test "transaction: false bypasses the wrapper (smoke)", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      reconcile_ctx = build_context(actor)
      plan = Runner.plan(reconcile_ctx, [{target.id, doc.id}])

      assert :ok = Runner.apply_plan!(reconcile_ctx, plan, transaction: false)
      assert {:ok, %_{}} = grant_for(target, doc)
    end
  end

  describe "failure surfacing" do
    test "a grant failure surfaces in run's return value" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      # An unknown strategy makes the granter chain error terminally —
      # the same propagation path as a flaky Ash.create inside a granter.
      ctx = build_context(actor, granter_chain: [:bogus_strategy])

      log =
        capture_log(fn ->
          assert {:error, %{grant_failures: [failure], revoke_failures: [], plan_errors: []}} =
                   Runner.run(ctx, [{target.id, doc.id}])

          assert failure == {target.id, doc.id, {:unknown_strategy, :bogus_strategy}}
        end)

      assert log =~ "grant issuance failed"
    end

    test "a revoke failure surfaces in run's return value" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Unauthorized grant (no membership) → the planner wants a revocation.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, target, @domain)

      ctx = build_context(actor)
      Process.put(:ash_envelope_fail_grant_destroy, true)

      log =
        capture_log(fn ->
          assert {:error,
                  %{
                    grant_failures: [],
                    revoke_failures: [{principal_id, subject_id, _reason}],
                    plan_errors: []
                  }} = Runner.run(ctx, [{target.id, doc.id}])

          assert principal_id == target.id
          assert subject_id == doc.id
        end)

      Process.delete(:ash_envelope_fail_grant_destroy)

      assert log =~ "revoke failed"
      # The de-authorized grant is still live — the caller MUST see the
      # error, because nothing else retries a failed revocation in sync mode.
      assert {:ok, %_{}} = grant_for(target, doc)

      # A clean retry revokes it.
      assert :ok = Runner.run(ctx, [{target.id, doc.id}])
      assert {:ok, nil} = grant_for(target, doc)
    end

    test "planner Plan.errors surface in run's return value" do
      actor = make_user(:user)
      target = make_user(:user)
      missing_subject_id = Ash.UUID.generate()

      ctx = build_context(actor)

      assert {:error,
              %{grant_failures: [], revoke_failures: [], plan_errors: [{principal_id, _reason}]}} =
               Runner.run(ctx, [{target.id, missing_subject_id}])

      assert principal_id == target.id
    end

    test "exhausted granter chain (:skip) is logged but not a failure" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()
      _ = make_membership(target, doc)

      # `:actor` skips (actor holds no grant); a never-matching `:request`
      # `when:` filter skips too — chain exhausted, still `:ok`.
      ctx =
        build_context(actor,
          granter_chain: [:actor, {:request, when: fn _target -> false end}]
        )

      log =
        capture_log(fn ->
          assert :ok = Runner.run(ctx, [{target.id, doc.id}])
        end)

      assert log =~ "chain exhausted"
    end
  end

  # SR8: lock the reconciliation correctness invariants beyond the example
  # tests above. We sample the four-cell truth table at random across many
  # principals, and we assert the wrap-binding invariant on the apply side:
  # a grant issued by apply_plan! MUST be openable with the target's
  # private key, and MUST NOT be openable with any other principal's
  # private key.
  describe "SR8 — reconciliation invariants" do
    test "plan/2 truth table: grant iff (should_grant ∧ ¬has_grant); revoke iff (¬should_grant ∧ has_grant)" do
      actor = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      # Seed 20 targets, each in one of the four cells. Membership ⇒
      # should_grant?; existing grant row ⇒ has_grant?.
      cells =
        for _ <- 1..20 do
          {should_grant?, has_grant?} = {Enum.random([true, false]), Enum.random([true, false])}
          target = make_user(:user)

          if should_grant? do
            _ = make_membership(target, doc)
          end

          if has_grant? do
            :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, target, @domain)
          end

          {target, should_grant?, has_grant?}
        end

      reconcile_ctx = build_context(actor)

      pairs = Enum.map(cells, fn {t, _, _} -> {t.id, doc.id} end)
      plan = Runner.plan(reconcile_ctx, pairs)

      grant_target_ids = MapSet.new(plan.grants, & &1.principal_id)
      revoke_target_ids = MapSet.new(plan.revocations, & &1.principal_id)

      for {target, should_grant?, has_grant?} <- cells do
        case {should_grant?, has_grant?} do
          {true, false} ->
            assert target.id in grant_target_ids,
                   "expected grant for #{target.id} (should_grant ∧ ¬has_grant)"

            refute target.id in revoke_target_ids

          {false, true} ->
            assert target.id in revoke_target_ids,
                   "expected revoke for #{target.id} (¬should_grant ∧ has_grant)"

            refute target.id in grant_target_ids

          {true, true} ->
            refute target.id in grant_target_ids,
                   "no-op when both should_grant and has_grant"

            refute target.id in revoke_target_ids

          {false, false} ->
            refute target.id in grant_target_ids,
                   "no-op when neither should_grant nor has_grant"

            refute target.id in revoke_target_ids
        end
      end
    end

    test "apply_plan! binds each wrap to the correct target only (no cross-principal openable)" do
      actor = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      targets = for _ <- 1..5, do: make_user(:user)
      Enum.each(targets, &make_membership(&1, doc))

      reconcile_ctx = build_context(actor)
      pairs = Enum.map(targets, &{&1.id, doc.id})
      :ok = Runner.run(reconcile_ctx, pairs)

      # For each target's grant row, the wrap MUST open with the target's
      # private key and MUST NOT open with any other principal's key.
      for target <- targets do
        {:ok, target_dek} =
          KeyGrants.resolve_for_actor(grants_config(), doc.id, target, @domain)

        assert target_dek == dek

        for other <- targets, other.id != target.id do
          # Resolving with `other` queries `(doc.id, other.id)` — that
          # row's wrap was made for `other`, not `target`. We also
          # explicitly verify the cross-unwrap fails by manually
          # fetching `target`'s wrap and trying to open with `other`'s
          # private key.
          {:ok, target_grant} = grant_for(target, doc)
          {:ok, raw_wrap} = Base.decode64(target_grant.wrapped_dek)

          assert {:error, :decryption_failed} =
                   AshEnvelope.unwrap_dek(raw_wrap, other.private_key)
        end
      end
    end
  end
end
