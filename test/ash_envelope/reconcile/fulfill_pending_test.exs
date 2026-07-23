defmodule AshEnvelope.Reconcile.FulfillPendingTest do
  use ExUnit.Case, async: true

  alias AshEnvelope.{GrantRequests, KeyGrants}

  alias AshEnvelope.Test.Reconcile.{
    DocumentWithAffects,
    Grant,
    GrantRequest,
    User
  }

  alias AshEnvelope.Reconcile.{Info, Runner}

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

  defp requests_config do
    %GrantRequests.Config{
      resource: GrantRequest,
      subject_id_attribute: :document_id
    }
  end

  defp build_ctx(actor) do
    {:ok, base} = Info.context(DocumentWithAffects)
    %{base | actor: actor}
  end

  defp seed_request(target, doc, requested_by) do
    :ok = GrantRequests.create(requests_config(), doc.id, target, requested_by, @domain)

    {:ok, req} =
      GrantRequest
      |> Ash.Query.filter(document_id == ^doc.id and user_id == ^target.id)
      |> Ash.Query.filter(is_nil(fulfilled_at))
      |> Ash.read_one(domain: @domain, authorize?: false)

    req
  end

  defp grant_for(user, doc) do
    Grant
    |> Ash.Query.filter(document_id == ^doc.id and user_id == ^user.id)
    |> Ash.read_one(domain: @domain, authorize?: false)
  end

  describe "fulfill_pending/3" do
    test "happy path: actor fulfills N requests, progress fires N times" do
      actor = make_user(:user)
      target_a = make_user(:user)
      target_b = make_user(:user)
      doc = make_document()

      # Actor seeds a DEK + grant for themselves.
      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      req_a = seed_request(target_a, doc, actor)
      req_b = seed_request(target_b, doc, actor)

      test_pid = self()
      progress_fun = fn meta -> send(test_pid, {:progress, meta}) end

      summary =
        Runner.fulfill_pending(build_ctx(actor), [req_a, req_b], on_progress: progress_fun)

      assert summary == %{ok: 2, skipped: 0, errors: []}

      # Progress messages.
      assert_received {:progress, %{done: 1, total: 2, status: :ok}}
      assert_received {:progress, %{done: 2, total: 2, status: :ok}}

      # Both targets now have grants and can resolve the DEK.
      assert {:ok, %_{}} = grant_for(target_a, doc)
      assert {:ok, %_{}} = grant_for(target_b, doc)

      {:ok, dek_a} = KeyGrants.resolve_for_actor(grants_config(), doc.id, target_a, @domain)
      assert dek_a == dek
    end

    test "idempotent: re-running with already-fulfilled rows returns :skipped" do
      actor = make_user(:user)
      target = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      req = seed_request(target, doc, actor)

      ctx = build_ctx(actor)

      summary1 = Runner.fulfill_pending(ctx, [req])
      assert summary1 == %{ok: 1, skipped: 0, errors: []}

      # Reload the now-fulfilled request.
      {:ok, [reloaded]} =
        GrantRequest
        |> Ash.Query.filter(id == ^req.id)
        |> Ash.read(domain: @domain, authorize?: false)

      assert reloaded.fulfilled_at != nil

      summary2 = Runner.fulfill_pending(ctx, [reloaded])
      assert summary2 == %{ok: 0, skipped: 1, errors: []}

      # No duplicate grant.
      assert {:ok, %_{}} = grant_for(target, doc)
    end

    test "target deleted between request and apply → counted as error, others process" do
      actor = make_user(:user)
      target_a = make_user(:user)
      target_b = make_user(:user)
      doc = make_document()

      dek = AshEnvelope.generate_dek()
      :ok = KeyGrants.create_for_actor(grants_config(), doc.id, dek, actor, @domain)

      req_a = seed_request(target_a, doc, actor)
      req_b = seed_request(target_b, doc, actor)

      :ok = Ash.destroy!(target_a, domain: @domain, authorize?: false, return_destroyed?: false)

      summary = Runner.fulfill_pending(build_ctx(actor), [req_a, req_b])

      assert summary.ok == 1
      assert summary.skipped == 0
      assert length(summary.errors) == 1
      assert {%_{id: id}, :target_not_found} = hd(summary.errors)
      assert id == req_a.id

      # target_b still got their grant.
      assert {:ok, %_{}} = grant_for(target_b, doc)
    end

    test "no actor in context → all requests error" do
      target = make_user(:user)
      doc = make_document()
      seeder = make_user(:user)
      req = seed_request(target, doc, seeder)

      summary = Runner.fulfill_pending(build_ctx(nil), [req])

      assert summary.ok == 0
      assert summary.skipped == 0
      assert [{%_{}, :no_actor}] = summary.errors
    end

    test "empty list returns zero summary, no progress fires" do
      actor = make_user(:user)
      test_pid = self()

      summary =
        Runner.fulfill_pending(build_ctx(actor), [],
          on_progress: fn _ -> send(test_pid, :unexpected) end
        )

      assert summary == %{ok: 0, skipped: 0, errors: []}
      refute_received :unexpected
    end
  end
end
