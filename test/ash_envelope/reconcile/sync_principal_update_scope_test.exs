defmodule AshEnvelope.Reconcile.SyncPrincipalUpdateScopeTest do
  # Not async: the async-mode test mutates Application env for the
  # enqueuer hook.
  use ExUnit.Case, async: false

  alias AshEnvelope.KeyGrants

  alias AshEnvelope.Test.Reconcile.{
    DocumentWithAffects,
    Grant,
    Membership,
    User
  }

  require Ash.Query

  @domain AshEnvelope.Test.Reconcile.Domain

  setup do
    parent = self()

    Application.put_env(
      :ash_envelope,
      :reconcile_async_enqueuer,
      fn args, queue -> send(parent, {:enqueued, args, queue}) end
    )

    on_exit(fn -> Application.delete_env(:ash_envelope, :reconcile_async_enqueuer) end)
    :ok
  end

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

  # Seeds: the actor holds the DEK on both documents; the target is a
  # member of `doc_a` and already holds a grant there. Returns the
  # membership row to move.
  defp seed_move_scenario(actor, target, doc_a, doc_b) do
    dek = AshEnvelope.generate_dek()
    :ok = KeyGrants.create_for_actor(grants_config(), doc_a.id, dek, actor, @domain)
    :ok = KeyGrants.create_for_actor(grants_config(), doc_b.id, dek, actor, @domain)

    {:ok, membership} =
      Ash.create(
        Membership,
        %{user_id: target.id, document_id: doc_a.id},
        action: :lookup_create,
        actor: actor,
        domain: @domain
      )

    assert {:ok, %_{}} = grant_for(target, doc_a)
    assert {:ok, nil} = grant_for(target, doc_b)

    membership
  end

  describe "update that changes the scope's inputs" do
    # Before the fix the scope function was evaluated against the
    # post-change changeset only, so the document the membership was
    # moved away from was never reconciled: the target lost read
    # authorization on it but kept the grant (and therefore the DEK).
    test "revokes the grant on the subject the principal no longer matches" do
      actor = make_user(:user)
      target = make_user(:user)
      doc_a = make_document()
      doc_b = make_document()

      membership = seed_move_scenario(actor, target, doc_a, doc_b)

      {:ok, _} =
        Ash.update(membership, %{document_id: doc_b.id},
          action: :move,
          actor: actor,
          domain: @domain
        )

      refute Ash.can?({doc_a, :read}, target)
      assert Ash.can?({doc_b, :read}, target)

      # Old subject revoked, new subject granted.
      assert {:ok, nil} = grant_for(target, doc_a)
      assert {:ok, %_{}} = grant_for(target, doc_b)
    end

    test "an update that changes nothing scope-relevant reconciles the current scope once" do
      actor = make_user(:user)
      target = make_user(:user)
      doc_a = make_document()
      doc_b = make_document()

      membership = seed_move_scenario(actor, target, doc_a, doc_b)

      # Same document_id: attributes map is non-empty but old == new, so
      # the union collapses to a single subject and nothing changes.
      {:ok, _} =
        Ash.update(membership, %{document_id: doc_a.id},
          action: :move,
          actor: actor,
          domain: @domain
        )

      assert {:ok, %_{}} = grant_for(target, doc_a)
      assert {:ok, nil} = grant_for(target, doc_b)
    end

    test "async mode enqueues both the old and the new subject" do
      actor = make_user(:user)
      target = make_user(:user)
      doc_a = make_document()
      doc_b = make_document()

      membership = seed_move_scenario(actor, target, doc_a, doc_b)

      {:ok, _} =
        Ash.update(membership, %{document_id: doc_b.id},
          action: :async_move,
          actor: actor,
          domain: @domain
        )

      assert_received {:enqueued, args, :ash_envelope_reconcile}
      assert args["principal_id"] == target.id
      assert Enum.sort(args["subject_ids"]) == Enum.sort([doc_a.id, doc_b.id])
    end
  end
end
