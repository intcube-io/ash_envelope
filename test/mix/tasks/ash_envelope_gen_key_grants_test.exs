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

    # The KeyGrants BlobIO manager keys grants by `bctx.blob.id` (the
    # owning record is not on the BlobContext for proxy / analyzer /
    # download reads). The scaffold must therefore hang grants off the
    # blob resource with the library-wide `:blob_id` default; a FK at
    # the owning record's table would fail every attach (FK violation)
    # and never line up with reconcile's lookups.
    test "belongs_to targets the blob resource with the :blob_id default" do
      notice = notice(@base_argv)

      assert notice =~
               ~r/belongs_to :blob, MyApp\.DocumentBlob do\s+source_attribute :blob_id/

      assert notice =~ "accept [:wrapped_dek, :blob_id, :user_id, :expires_at]"
      refute notice =~ ~r/belongs_to :document, MyApp\.Document/
      refute notice =~ ~r/^\s*(source_attribute|add) :document_id/m
    end

    test "a custom --file-id-attribute flows into every place the FK is named" do
      notice = notice(@base_argv ++ ["--file-id-attribute", "blob_ref_id"])

      assert notice =~
               ~r/belongs_to :blob, MyApp\.DocumentBlob do\s+source_attribute :blob_ref_id/

      # create action accepts the same attribute the relationship writes
      assert notice =~ "accept [:wrapped_dek, :blob_ref_id, :user_id, :expires_at]"
      # key manager + reconcile read/write the same column
      assert notice =~ "subject_id_attribute: :blob_ref_id"
      assert notice =~ "key_grants_subject_id_attribute :blob_ref_id"
      # inverse relationship on the blob resource is pinned to the FK
      assert notice =~
               ~r/has_many :key_grants, MyApp\.FileKeyGrant do\s+destination_attribute :blob_ref_id/
    end

    test "--blob-resource overrides the inferred blob module everywhere" do
      notice = notice(@base_argv ++ ["--blob-resource", "MyApp.Storage.Blob"])

      assert notice =~ ~r/belongs_to :blob, MyApp\.Storage\.Blob do/
      assert notice =~ "blob_resource MyApp.Storage.Blob"
      assert notice =~ "references(:blobs, type: :uuid, on_delete: :delete_all)"
      refute notice =~ "MyApp.DocumentBlob"
    end
  end

  describe "reconcile block scaffold" do
    test "maps a record to its blob id so reconcile and the manager agree on the subject" do
      notice = notice(@base_argv)

      assert notice =~ "key_grants_subject_id_attribute :blob_id"
      assert notice =~ "subject_load [:file]"
      assert notice =~ "subject_id_for fn record -> record.file && record.file.blob_id end"
    end

    test "--file-attribute is the relationship walked by subject_id_for" do
      notice = notice(@base_argv ++ ["--file-attribute", "scan"])

      assert notice =~ "subject_load [:scan]"
      assert notice =~ "subject_id_for fn record -> record.scan && record.scan.blob_id end"
    end
  end

  describe "encrypted resource storage block" do
    # The pinned ash_storage DSL has no `layers [...]` option and no
    # `layer_id:`; a `storage do` block in that shape fails to compile
    # with "undefined function layers/1". The scaffold must emit one
    # `layer` entity with a `metadata_key` plus the required
    # `blob_resource` / `attachment_resource` fields.
    test "emits a layer entity with metadata_key, not a layers list" do
      notice = notice(@base_argv)

      assert notice =~ ~r/layer \{AshStorage\.Layer\.Encryption,/
      assert notice =~ ~s{metadata_key: "document-vault"}
      assert notice =~ "blob_resource MyApp.DocumentBlob"
      assert notice =~ "attachment_resource MyApp.DocumentAttachment"
      assert notice =~ "has_one_attached :file"

      # Anchored to a DSL line so the explanatory prose ("there is no
      # `layers [...]` list") doesn't trip the check.
      refute notice =~ ~r/^\s*layers \[/m
      refute notice =~ ~r/^\s*layer_id:/m
    end

    test "--file-attribute names the attachment declared on the resource" do
      notice = notice(@base_argv ++ ["--file-attribute", "scan"])

      assert notice =~ "has_one_attached :scan"
      assert notice =~ "attachment: :scan"
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

    test "subject FK references the blob table, not the owning record's table" do
      notice = notice(@base_argv)

      assert notice =~
               ~r/add :blob_id,\s+references\(:document_blobs, type: :uuid, on_delete: :delete_all\)/

      refute notice =~ "references(:documents"
    end

    test "warns that inferred table names must be verified" do
      notice = notice(@base_argv)

      assert notice =~ "VERIFY TABLE NAMES"
      assert notice =~ ~s{"document_blobs" and "users"}
    end
  end
end
