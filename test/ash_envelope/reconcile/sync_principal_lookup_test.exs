defmodule AshEnvelope.Reconcile.SyncPrincipalLookupTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.KeyGrants

  alias AshEnvelope.Test.Reconcile.{
    DocumentWithAffects,
    Grant,
    GrantRequest,
    Membership,
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

  describe "lookup-form SyncPrincipal on `:lookup_create`" do
    test "creates a grant when actor holds the DEK" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Actor uploaded the doc and holds the only grant.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      # Membership.lookup_create should reconcile via the affects entry.
      {:ok, _membership} =
        Ash.create(
          Membership,
          %{user_id: target.id, document_id: doc.id},
          action: :lookup_create,
          actor: actor,
          domain: @domain
        )

      assert {:ok, %_{}} = grant_for(target, doc)

      # Target can resolve the same DEK.
      {:ok, target_dek} = KeyGrants.resolve_for_actor(grants_config(), doc.id, target, @domain)
      assert target_dek == dek
    end

    test "queues a pending request when actor has no grant" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      {:ok, _membership} =
        Ash.create(
          Membership,
          %{user_id: target.id, document_id: doc.id},
          action: :lookup_create,
          actor: actor,
          domain: @domain
        )

      # No grant for actor (nothing to share from) → falls through to :request.
      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, %_{}} = pending_request_for(target, doc)
    end
  end

  describe "lookup-form SyncPrincipal on `:lookup_destroy`" do
    test "revokes the target's grant when their membership goes away" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # Seed: actor has the DEK, target has been granted via membership.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      {:ok, membership} =
        Ash.create(
          Membership,
          %{user_id: target.id, document_id: doc.id},
          action: :lookup_create,
          actor: actor,
          domain: @domain
        )

      assert {:ok, %_{}} = grant_for(target, doc)

      # Destroy the membership via the lookup-form action.
      :ok =
        Ash.destroy!(membership,
          action: :lookup_destroy,
          actor: actor,
          domain: @domain,
          return_destroyed?: false
        )

      assert {:ok, nil} = grant_for(target, doc)
    end
  end

  describe "lookup hits no entry" do
    test "no `affects` entry for a non-listed action ⇒ change is a no-op" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      # An action whose name isn't in `affects.actions` won't trigger
      # reconciliation. Membership has a regular `:create` action that
      # doesn't include the SyncPrincipal change at all, so no grant is
      # ever created for the target.
      {:ok, _} =
        Ash.create(
          Membership,
          %{user_id: target.id, document_id: doc.id},
          action: :create,
          actor: actor,
          domain: @domain,
          authorize?: false
        )

      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end
  end
end
