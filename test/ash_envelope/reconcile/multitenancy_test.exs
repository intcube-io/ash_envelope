defmodule AshEnvelope.Reconcile.MultitenancyTest do
  # Not async: the async-mode tests mutate Application env for the
  # enqueuer hook.
  use ExUnit.Case, async: false

  alias AshEnvelope.KeyGrants

  alias AshEnvelope.Test.Reconcile.{
    Grant,
    GrantRequest,
    MtDocument,
    MtMembership,
    User
  }

  alias AshEnvelope.Reconcile.AsyncWorker

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

    # ETS tables persist across tests in the run, and MtDocument's
    # affects entry uses `scope :all` — unique tenant names keep each
    # test's fan-out from seeing other tests' documents.
    %{tenant_a: "org-a-#{Ash.UUID.generate()}", tenant_b: "org-b-#{Ash.UUID.generate()}"}
  end

  defp make_user(role) do
    {pub, priv} = AshEnvelope.generate_key_pair()

    {:ok, user} =
      Ash.create(User, %{role: role, public_key: pub, private_key: priv}, domain: @domain)

    user
  end

  defp make_document(tenant) do
    {:ok, doc} =
      Ash.create(MtDocument, %{title: "doc-#{Ash.UUID.generate()}"},
        tenant: tenant,
        domain: @domain
      )

    doc
  end

  # Seeds a membership without firing reconciliation.
  defp seed_membership(user, doc, tenant) do
    {:ok, _} =
      Ash.create(
        MtMembership,
        %{user_id: user.id, document_id: doc.id},
        action: :seed,
        tenant: tenant,
        authorize?: false,
        domain: @domain
      )

    :ok
  end

  defp grants_config do
    %KeyGrants.Config{
      resource: Grant,
      subject_id_attribute: :document_id,
      actor_public_key_attribute: :public_key,
      actor_private_key_attribute: :private_key
    }
  end

  defp grant_for(user, doc) do
    Grant
    |> Ash.Query.filter(document_id == ^doc.id and user_id == ^user.id)
    |> Ash.read_one(domain: @domain, authorize?: false)
  end

  defp pending_request_for(user, doc) do
    GrantRequest
    |> Ash.Query.filter(document_id == ^doc.id and user_id == ^user.id)
    |> Ash.Query.filter(is_nil(fulfilled_at))
    |> Ash.read_one(domain: @domain, authorize?: false)
  end

  describe "sync fan-out is tenant-scoped" do
    # MtDocument's affects entry uses `scope :all` — the widest possible
    # fan-out. With `global? true` a tenant-less stream would return
    # documents of EVERY tenant; this locks in that the stream inherits
    # the triggering changeset's tenant instead.
    test "scope :all only enumerates subjects in the triggering tenant", ctx do
      actor = make_user(:user)
      target = make_user(:user)

      doc_a = make_document(ctx.tenant_a)
      doc_b = make_document(ctx.tenant_b)

      # The target is also a member of the tenant-B document (seeded
      # without a trigger). If the fan-out crossed tenants, reconcile
      # would see the target as authorized on doc_b and queue a request
      # for it too.
      :ok = seed_membership(target, doc_b, ctx.tenant_b)

      # Actor holds no grant, so the chain falls through to :request.
      {:ok, _} =
        Ash.create(
          MtMembership,
          %{user_id: target.id, document_id: doc_a.id},
          action: :create,
          actor: actor,
          tenant: ctx.tenant_a,
          domain: @domain
        )

      assert {:ok, %_{}} = pending_request_for(target, doc_a)
      assert {:ok, nil} = pending_request_for(target, doc_b)
      assert {:ok, nil} = grant_for(target, doc_b)
    end

    test "grant issuance stays within the triggering tenant", ctx do
      actor = make_user(:user)
      target = make_user(:user)

      doc_a = make_document(ctx.tenant_a)
      doc_b = make_document(ctx.tenant_b)
      :ok = seed_membership(target, doc_b, ctx.tenant_b)

      # Actor holds the DEK for both docs, so :actor could grant either —
      # only the tenant-A pair may be reconciled.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc_a.id, dek, actor, @domain)
      :ok = KeyGrants.create_for_actor(grants_config(), doc_b.id, dek, actor, @domain)

      {:ok, _} =
        Ash.create(
          MtMembership,
          %{user_id: target.id, document_id: doc_a.id},
          action: :create,
          actor: actor,
          tenant: ctx.tenant_a,
          domain: @domain
        )

      assert {:ok, %_{}} = grant_for(target, doc_a)
      assert {:ok, nil} = grant_for(target, doc_b)
      assert {:ok, nil} = pending_request_for(target, doc_b)
    end

    # The nastiest cross-tenant failure: if the `scope :all` stream is
    # not tenant-scoped, the planner also classifies pairs in OTHER
    # tenants — where the tenant-A-scoped `Ash.can?` correctly says
    # "not authorized" — and revokes those tenants' perfectly valid
    # grants.
    test "does not revoke another tenant's valid grants", ctx do
      actor = make_user(:user)
      target = make_user(:user)

      doc_a = make_document(ctx.tenant_a)
      doc_b = make_document(ctx.tenant_b)

      # Target legitimately holds a grant on the tenant-B document.
      :ok = seed_membership(target, doc_b, ctx.tenant_b)
      dek_b = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc_b.id, dek_b, target, @domain)

      {:ok, _} =
        Ash.create(
          MtMembership,
          %{user_id: target.id, document_id: doc_a.id},
          action: :create,
          actor: actor,
          tenant: ctx.tenant_a,
          domain: @domain
        )

      # The tenant-B grant must be untouched by the tenant-A fan-out.
      assert {:ok, %_{}} = grant_for(target, doc_b)
    end
  end

  describe "async job args carry the tenant" do
    test "trigger serializes the changeset tenant into the job args", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document(ctx.tenant_a)

      # A doc in another tenant must not appear in the enqueued
      # subject_ids — the scope resolution itself is tenant-scoped.
      other = make_document(ctx.tenant_b)

      {:ok, _} =
        Ash.create(
          MtMembership,
          %{user_id: target.id, document_id: doc.id},
          action: :async_create,
          actor: actor,
          tenant: ctx.tenant_a,
          domain: @domain
        )

      assert_received {:enqueued, args, _queue}
      assert args["tenant"] == ctx.tenant_a
      assert args["principal_id"] == target.id
      assert doc.id in args["subject_ids"]
      refute other.id in args["subject_ids"]
    end

    test "single-tenant hosts enqueue a nil tenant (no behavior change)", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document(ctx.tenant_a)

      # No tenant on the trigger — mirrors today's single-tenant callers.
      # With `global? true` the tenant-less fan-out spans all tenants,
      # exactly as before this change.
      {:ok, _} =
        Ash.create(
          MtMembership,
          %{user_id: target.id, document_id: doc.id, org_id: ctx.tenant_a},
          action: :async_create,
          actor: actor,
          authorize?: false,
          domain: @domain
        )

      assert_received {:enqueued, args, _queue}
      assert args["tenant"] == nil
      assert doc.id in args["subject_ids"]
    end
  end

  describe "AsyncWorker restores the tenant" do
    test "worker runs the pair tenant-scoped and issues the grant", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document(ctx.tenant_a)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)
      :ok = seed_membership(target, doc, ctx.tenant_a)

      args = %{
        "encrypted_resource" => "Elixir.AshEnvelope.Test.Reconcile.MtDocument",
        "principal_id" => target.id,
        "actor_id" => actor.id,
        "subject_ids" => [doc.id],
        "tenant" => ctx.tenant_a
      }

      assert :ok = AsyncWorker.perform(%Oban.Job{args: args})

      assert {:ok, %_{}} = grant_for(target, doc)

      {:ok, target_dek} = KeyGrants.resolve_for_actor(grants_config(), doc.id, target, @domain)
      assert target_dek == dek
    end

    test "authorization is evaluated under the job's tenant, not globally", ctx do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document(ctx.tenant_a)

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      # The target's membership on this document exists only under
      # tenant B. A tenant-less `Ash.can?` would see it and issue a
      # grant; scoped to tenant A it must not.
      :ok = seed_membership(target, doc, ctx.tenant_b)

      args = %{
        "encrypted_resource" => "Elixir.AshEnvelope.Test.Reconcile.MtDocument",
        "principal_id" => target.id,
        "actor_id" => actor.id,
        "subject_ids" => [doc.id],
        "tenant" => ctx.tenant_a
      }

      assert :ok = AsyncWorker.perform(%Oban.Job{args: args})

      assert {:ok, nil} = grant_for(target, doc)
      assert {:ok, nil} = pending_request_for(target, doc)
    end
  end
end
