defmodule AshEnvelope.Reconcile.GranterWhenTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.{KeyGrants}

  alias AshEnvelope.Test.Reconcile.{
    DocumentWithAffects,
    Grant,
    GrantRequest,
    User
  }

  alias AshEnvelope.Reconcile.{Granter, Info}

  require Ash.Query

  @domain AshEnvelope.Test.Reconcile.Domain

  defp make_user(role) do
    {pub, priv} = AshEnvelope.generate_key_pair()

    {:ok, user} =
      Ash.create(User, %{role: role, public_key: pub, private_key: priv}, domain: @domain)

    user
  end

  defp make_document do
    {:ok, doc} =
      Ash.create(DocumentWithAffects, %{title: "doc-#{Ash.UUID.generate()}"}, domain: @domain)

    doc
  end

  defp grants_config do
    %KeyGrants.Config{
      resource: Grant,
      subject_id_attribute: :document_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
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

  defp build_ctx(actor, chain) do
    {:ok, base} = Info.context(DocumentWithAffects)
    %{base | actor: actor, granter_chain: chain}
  end

  describe ":when filter on tuple-form strategies" do
    test "predicate returning false skips the strategy" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Seed actor with a grant so :actor would otherwise succeed.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx = build_ctx(actor, [{:actor, when: fn _target, _ctx -> false end}, :request])

      assert :ok = Granter.try_chain(ctx, doc, doc.id, target)

      # Skipped :actor → fell through to :request.
      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, %_{}} = pending_request_for(target, doc)
    end

    test "predicate returning true permits the strategy" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx = build_ctx(actor, [{:actor, when: fn _target, _ctx -> true end}, :request])

      assert :ok = Granter.try_chain(ctx, doc, doc.id, target)

      # :actor fired → grant exists, no pending request.
      assert {:ok, %_{}} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end

    test "1-arity predicate works" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx =
        build_ctx(actor, [
          {:actor, when: fn target -> target.role == :admin end},
          :request
        ])

      assert :ok = Granter.try_chain(ctx, doc, doc.id, target)

      # target.role is :user, predicate false → skipped → :request fired.
      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, %_{}} = pending_request_for(target, doc)
    end

    test "self_or_recovery pattern: actor fires for self and recovery, requests for others" do
      actor = make_user(:user)
      recovery = make_user(:recovery)
      other = make_user(:user)
      doc = make_document()

      # Actor needs a grant to share from.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      self_or_recovery? = fn target, %{actor: %{id: actor_id}} ->
        target.id == actor_id or target.role == :recovery
      end

      ctx = build_ctx(actor, [{:actor, when: self_or_recovery?}, :request])

      # recovery → :actor fires inline.
      assert :ok = Granter.try_chain(ctx, doc, doc.id, recovery)
      assert {:ok, %_{}} = grant_for(recovery, doc)
      assert {:ok, nil} = pending_request_for(recovery, doc)

      # other → :actor skipped, :request fires.
      assert :ok = Granter.try_chain(ctx, doc, doc.id, other)
      assert {:ok, nil} = grant_for(other, doc)
      assert {:ok, %_{}} = pending_request_for(other, doc)
    end

    test "predicate is honored on :request strategy too" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      ctx = build_ctx(actor, [{:request, when: fn _target -> false end}])

      # :request gated off → chain falls through to no strategies left.
      assert :skip = Granter.try_chain(ctx, doc, doc.id, target)
      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end

    test "missing :when key behaves like always-true" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx = build_ctx(actor, [{:actor, []}, :request])

      assert :ok = Granter.try_chain(ctx, doc, doc.id, target)
      assert {:ok, %_{}} = grant_for(target, doc)
    end
  end

  describe "tuple form preserves bare-atom semantics" do
    test "{:actor, []} behaves identically to :actor" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      ctx = build_ctx(actor, [{:actor, []}])
      assert :ok = Granter.try_chain(ctx, doc, doc.id, target)
      assert {:ok, %_{}} = grant_for(target, doc)
    end

    test "{:request, []} behaves identically to :request" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      ctx = build_ctx(actor, [{:request, []}])
      assert :ok = Granter.try_chain(ctx, doc, doc.id, target)
      assert {:ok, %_{}} = pending_request_for(target, doc)
    end
  end
end
