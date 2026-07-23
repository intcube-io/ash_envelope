defmodule AshEnvelope.Reconcile.AffectingExtensionTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.KeyGrants

  alias AshEnvelope.Test.Reconcile.{
    AffectingMembership,
    DocumentWithAffects,
    Grant,
    GrantRequest,
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

  describe "auto-injected SyncPrincipal" do
    test "fires on :create without per-action wire-up" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      {:ok, _membership} =
        Ash.create(
          AffectingMembership,
          %{user_id: target.id, document_id: doc.id},
          actor: actor,
          domain: @domain,
          authorize?: false
        )

      assert {:ok, %_{}} = grant_for(target, doc)

      {:ok, target_dek} = KeyGrants.resolve_for_actor(grants_config(), doc.id, target, @domain)
      assert target_dek == dek
    end

    test "fires on :destroy without per-action wire-up" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      {:ok, membership} =
        Ash.create(
          AffectingMembership,
          %{user_id: target.id, document_id: doc.id},
          actor: actor,
          domain: @domain,
          authorize?: false
        )

      assert {:ok, %_{}} = grant_for(target, doc)

      :ok =
        Ash.destroy!(membership,
          actor: actor,
          domain: @domain,
          authorize?: false,
          return_destroyed?: false
        )

      assert {:ok, nil} = grant_for(target, doc)
    end

    test "no-ops for actions whose type isn't listed by the encrypted resource" do
      # `:touch` is an `:update` action on `AffectingMembership`. The
      # encrypted resource's `affects AffectingMembership` entry lists
      # only `[:create, :destroy]`, so the auto-injected change must
      # silently skip — no new grant or request gets written.
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      {:ok, membership} =
        Ash.create(
          AffectingMembership,
          %{user_id: target.id, document_id: doc.id},
          actor: actor,
          domain: @domain,
          authorize?: false
        )

      # Reset both grants and pending requests created by `:create` so
      # we can detect any re-fire from `:touch`.
      Grant
      |> Ash.Query.filter(document_id == ^doc.id and user_id == ^target.id)
      |> Ash.bulk_destroy!(:destroy, %{}, domain: @domain, authorize?: false)

      GrantRequest
      |> Ash.Query.filter(document_id == ^doc.id and user_id == ^target.id)
      |> Ash.bulk_destroy!(:destroy, %{}, domain: @domain, authorize?: false)

      {:ok, _} =
        Ash.update(membership, %{}, action: :touch, domain: @domain, authorize?: false)

      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end
  end
end
