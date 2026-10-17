defmodule Mix.Tasks.AshEnvelope.Gen.GrantRequestsTest do
  @moduledoc """
  The gen.grant_requests task emits a single Igniter notice of paste-me
  scaffold code. These tests lock in that the migration scaffold derives
  its user-side `references(...)` from `--user-resource` and flags
  inferred table names for verification.
  """

  use ExUnit.Case, async: true

  import Igniter.Test

  @base_argv [
    "MyApp.Document",
    "--requests-resource",
    "MyApp.DocumentGrantRequest",
    "--grants-resource",
    "MyApp.DocumentKeyGrant",
    "--domain",
    "MyApp.Catalog",
    "--user-resource",
    "MyApp.User"
  ]

  defp notice(argv) do
    igniter = Igniter.compose_task(test_project(), "ash_envelope.gen.grant_requests", argv)

    assert [notice] = igniter.notices
    notice
  end

  describe "requests resource scaffold" do
    test "the create action is primary" do
      notice = notice(@base_argv)

      assert notice =~ ~r/create :create do\s+primary\? true/
    end

    # Reconcile hands `GrantRequests.create/6` the grant subject id, which
    # the KeyGrants BlobIO manager derives from `bctx.blob.id`. The
    # requests table must therefore be keyed by the blob row like the
    # grants table, with the same `:blob_id` default.
    test "belongs_to targets the blob resource with the :blob_id default" do
      notice = notice(@base_argv)

      assert notice =~
               ~r/belongs_to :blob, MyApp\.DocumentBlob do\s+source_attribute :blob_id/

      assert notice =~ "subject_id_attribute: :blob_id"
      refute notice =~ ~r/belongs_to :document, MyApp\.Document/
    end

    test "--blob-resource and --subject-id-attribute flow through" do
      notice =
        notice(
          @base_argv ++
            ["--blob-resource", "MyApp.Storage.Blob", "--subject-id-attribute", "blob_ref_id"]
        )

      assert notice =~
               ~r/belongs_to :blob, MyApp\.Storage\.Blob do\s+source_attribute :blob_ref_id/

      assert notice =~ ~r/add :blob_ref_id,\s+references\(:blobs, type: :uuid/
      assert notice =~ "subject_id_attribute: :blob_ref_id"
    end
  end

  describe "migration scaffold" do
    test "subject FK references the blob table, not the owning record's table" do
      notice = notice(@base_argv)

      assert notice =~
               ~r/add :blob_id,\s+references\(:document_blobs, type: :uuid, on_delete: :delete_all\)/

      refute notice =~ "references(:documents"
    end

    test "user FKs reference the table derived from --user-resource" do
      notice = notice(@base_argv)

      assert notice =~
               ~r/add :user_id,\s+references\(:users, type: :uuid, on_delete: :delete_all\)/
    end

    test "a custom user resource changes all three user-side references" do
      argv = List.replace_at(@base_argv, length(@base_argv) - 1, "MyApp.Accounts.Member")
      notice = notice(argv)

      assert notice =~
               ~r/add :user_id,\s+references\(:members, type: :uuid, on_delete: :delete_all\)/

      assert notice =~
               ~r/add :requested_by_id,\s+references\(:members, type: :uuid, on_delete: :nilify_all\)/

      assert notice =~
               ~r/add :fulfilled_by_id,\s+references\(:members, type: :uuid, on_delete: :nilify_all\)/

      refute notice =~ "references(:users"
    end

    test "warns that inferred table names must be verified" do
      notice = notice(@base_argv)

      assert notice =~ "VERIFY TABLE NAMES"
      assert notice =~ ~s{"document_blobs" and "users"}
    end
  end
end
