defmodule AshEnvelope.Reconcile.AffectsDslTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.Reconcile.{Affects, Info}

  alias AshEnvelope.Test.Reconcile.{DocumentWithAffects, Membership, User}

  describe "DSL parsing" do
    test "Info.affects/1 returns every entry on the resource" do
      entries = Info.affects(DocumentWithAffects)

      assert length(entries) == 3
      assert Enum.all?(entries, &match?(%Affects{}, &1))
    end

    test "entries preserve resource / actions / principal" do
      [membership_entry] = Info.affects_for(DocumentWithAffects, Membership)

      assert membership_entry.resource == Membership

      assert membership_entry.actions == [
               :create,
               :destroy,
               :lookup_create,
               :lookup_destroy,
               :async_create,
               :async_destroy
             ]

      assert membership_entry.principal == :user_id
    end

    test "scope :all is stored as the atom" do
      [user_entry] = Info.affects_for(DocumentWithAffects, User)
      assert user_entry.scope == :all
    end

    test "scope as a fn lifts to a callable function" do
      [m_entry] = Info.affects_for(DocumentWithAffects, Membership)

      assert is_function(m_entry.scope, 1)

      doc_id = Ash.UUID.generate()

      cs =
        Ash.Changeset.for_create(Membership, :create, %{
          user_id: Ash.UUID.generate(),
          document_id: doc_id
        })

      assert [id: ^doc_id] = m_entry.scope.(cs)
    end

    test "only_when as a fn lifts to a callable function" do
      [user_entry] = Info.affects_for(DocumentWithAffects, User)

      assert is_function(user_entry.only_when, 1)

      {pub, priv} = AshEnvelope.generate_key_pair()

      {:ok, user} =
        Ash.create(User, %{role: :user, public_key: pub, private_key: priv},
          domain: AshEnvelope.Test.Reconcile.Domain
        )

      cs_no_role = Ash.Changeset.for_update(user, :update, %{public_key: "x"})
      cs_with_role = Ash.Changeset.for_update(user, :update, %{role: :admin})

      refute user_entry.only_when.(cs_no_role)
      assert user_entry.only_when.(cs_with_role)
    end

    test "missing only_when stays nil" do
      [m_entry] = Info.affects_for(DocumentWithAffects, Membership)
      assert is_nil(m_entry.only_when)
    end
  end

  describe "Info.affects_for_action/3" do
    test "returns the entry whose actions list contains the given action" do
      assert %Affects{principal: :user_id} =
               Info.affects_for_action(DocumentWithAffects, Membership, :create)

      assert %Affects{principal: :user_id} =
               Info.affects_for_action(DocumentWithAffects, Membership, :destroy)
    end

    test "returns nil when the action falls outside the declared subset" do
      # Membership.update isn't in the affects entry's actions list.
      assert is_nil(Info.affects_for_action(DocumentWithAffects, Membership, :update))
    end

    test "returns nil when no entry targets the affecting resource" do
      # No `affects AshEnvelope.Test.Reconcile.Grant do … end` block declared,
      # so a lookup for that resource yields nothing.
      assert is_nil(
               Info.affects_for_action(
                 DocumentWithAffects,
                 AshEnvelope.Test.Reconcile.Grant,
                 :create
               )
             )
    end
  end
end
