defmodule Mix.Tasks.AshEnvelope.Gen.KeyGrantsTest do
  @moduledoc """
  The gen.key_grants task emits a single Igniter notice full of paste-me
  scaffold code. These tests lock in the correctness of that scaffold
  text: primary actions, `source_attribute` for custom FK names, an
  actor-threaded revoke handler, and migration `references(...)` derived
  from `--user-resource`.
  """

  use ExUnit.Case, async: true

  import Igniter.Test

  @base_argv [
    "MyApp.Document",
    "--grants-resource",
    "MyApp.FileKeyGrant",
    "--domain",
    "MyApp.Catalog",
    "--user-resource",
    "MyApp.User"
  ]

  defp notice(argv) do
    igniter = Igniter.compose_task(test_project(), "ash_envelope.gen.key_grants", argv)

    assert [notice] = igniter.notices
    notice
  end

  describe "grants resource scaffold" do
    test "the create action is primary so KeyGrants.create_for_actor can Ash.create" do
      notice = notice(@base_argv)

      assert notice =~ ~r/create :create do\s+primary\? true/
    end

    test "read and destroy come from defaults (primary by construction)" do
      notice = notice(@base_argv)

      assert notice =~ "defaults [:read, :destroy]"
    end

    test "belongs_to pins source_attribute to the file id attribute" do
      notice = notice(@base_argv)

      assert notice =~
               ~r/belongs_to :document, MyApp\.Document do\s+source_attribute :document_id/
    end

    test "a custom --file-id-attribute is used as the belongs_to source_attribute" do
      notice = notice(@base_argv ++ ["--file-id-attribute", "blob_ref_id"])

      assert notice =~
               ~r/belongs_to :document, MyApp\.Document do\s+source_attribute :blob_ref_id/

      # create action accepts the same attribute the relationship writes
      assert notice =~ "accept [:wrapped_dek, :blob_ref_id, :user_id, :expires_at]"
    end
  end

  describe "LiveView revoke handler scaffold" do
    test "fetches the grant as the current user with authorization enabled" do
      notice = notice(@base_argv)

      assert notice =~ "actor = socket.assigns.current_user"
      assert notice =~ "Ash.get(MyApp.FileKeyGrant, grant_id, actor: actor, authorize?: true)"

      refute notice =~ "Ash.get(MyApp.FileKeyGrant, grant_id, authorize?: false)"
    end

    test "passes the actor to KeyGrants.revoke so the destroy policy applies" do
      notice = notice(@base_argv)

      assert notice =~ "AshEnvelope.KeyGrants.revoke(grant, MyApp.Catalog, actor: actor)"
      refute notice =~ "AshEnvelope.KeyGrants.revoke(grant, MyApp.Catalog) do"
    end
  end

  describe "migration scaffold" do
    test "user FK references the table derived from --user-resource" do
      notice = notice(@base_argv)

      assert notice =~ "add :user_id, references(:users, type: :uuid), null: true"
    end

    test "a custom user resource changes the referenced table" do
      argv = List.replace_at(@base_argv, length(@base_argv) - 1, "MyApp.Accounts.Member")
      notice = notice(argv)

      assert notice =~ "add :user_id, references(:members, type: :uuid), null: true"
      refute notice =~ "references(:users"
    end

    test "warns that inferred table names must be verified" do
      notice = notice(@base_argv)

      assert notice =~ "VERIFY TABLE NAMES"
      assert notice =~ ~s{"documents" and "users"}
    end
  end
end
