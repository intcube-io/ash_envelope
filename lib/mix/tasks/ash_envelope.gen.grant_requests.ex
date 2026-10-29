defmodule Mix.Tasks.AshEnvelope.Gen.GrantRequests do
  @moduledoc """
  Generates pending grant request infrastructure.

  A grant request is a pending "this user should get a grant on this
  subject, but the actor at the time couldn't issue it" row. Useful when
  the actor whose action grants new access does not themselves hold a
  grant on the subject and therefore cannot wrap the DEK to a new
  recipient. See `AshEnvelope.GrantRequests` and the `AshEnvelope.Reconcile`
  extension's `:request` granter strategy.

  Creates instructions for:
  - A grant requests Ash resource (stores pending requests + fulfilled rows)
  - An Ecto migration for the table
  - Domain registration
  - Suggested fulfillment hooks (login-time, admin panel)

  ## Usage

      mix ash_envelope.gen.grant_requests MyApp.Document \\
        --requests-resource MyApp.DocumentGrantRequest \\
        --grants-resource MyApp.DocumentKeyGrant \\
        --domain MyApp.Catalog \\
        --user-resource MyApp.User

  ## Options

  * `--requests-resource` - Module name for the grant requests resource (required)
  * `--grants-resource` - Module name of the existing key grants resource (required)
  * `--domain` - The Ash domain module (required)
  * `--user-resource` - The user/actor resource module (required)
  * `--blob-resource` - The `AshStorage.BlobResource` module the subject's
    attachment stores into. Requests are keyed by the blob row, like the
    grants table (default: inferred from the resource name, e.g.
    MyApp.Document -> MyApp.DocumentBlob)
  * `--subject-id-attribute` - FK on the requests table pointing at the blob
    row. Must match the grants resource / `reconcile do` convention
    (default: `:blob_id`)
  * `--repo` - The Ecto repo module (default: inferred from domain)
  """

  use Igniter.Mix.Task

  @impl Igniter.Mix.Task
  def info(_argv, _parent) do
    %Igniter.Mix.Task.Info{
      positional: [:resource],
      schema: [
        requests_resource: :string,
        grants_resource: :string,
        domain: :string,
        user_resource: :string,
        blob_resource: :string,
        subject_id_attribute: :string,
        repo: :string
      ],
      required: [:requests_resource, :grants_resource, :domain, :user_resource]
    }
  end

  @impl Igniter.Mix.Task
  def igniter(igniter) do
    resource = Igniter.Project.Module.parse(igniter.args.positional.resource)
    requests_resource = Igniter.Project.Module.parse(igniter.args.options[:requests_resource])
    grants_resource = Igniter.Project.Module.parse(igniter.args.options[:grants_resource])
    domain = Igniter.Project.Module.parse(igniter.args.options[:domain])
    user_resource = Igniter.Project.Module.parse(igniter.args.options[:user_resource])
    blob_resource = infer_blob_resource(igniter.args.options[:blob_resource], resource)

    # Same subject id as the grants table: reconcile passes the grant
    # subject id (the blob id, see `mix ash_envelope.gen.key_grants`) to
    # `AshEnvelope.GrantRequests.create/6`, so the FK must reference the
    # blob table and defaults to the library-wide `:blob_id`.
    subject_id_attr =
      if igniter.args.options[:subject_id_attribute] do
        String.to_atom(igniter.args.options[:subject_id_attribute])
      else
        :blob_id
      end

    repo = infer_repo(igniter.args.options[:repo], domain)
    requests_table = infer_table_name(requests_resource)
    blob_table = infer_table_name(blob_resource)
    user_table = infer_table_name(user_resource)

    igniter
    |> Igniter.add_notice("""
    ══════════════════════════════════════════════════════════════════
    Pending Grant Requests Setup for #{inspect(resource)}
    ══════════════════════════════════════════════════════════════════

    ┌─────────────────────────────────────────────────────────────┐
    │ 1. CREATE THE GRANT REQUESTS RESOURCE                      │
    └─────────────────────────────────────────────────────────────┘

    Create the file: #{requests_resource_path(requests_resource)}

    defmodule #{inspect(requests_resource)} do
      use Ash.Resource,
        domain: #{inspect(domain)},
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer]

      postgres do
        table "#{requests_table}"
        repo #{inspect(repo)}
      end

      attributes do
        uuid_primary_key :id

        attribute :requested_at, :utc_datetime_usec do
          allow_nil? false
          public? true
        end

        attribute :fulfilled_at, :utc_datetime_usec do
          allow_nil? true
          public? true
        end

        attribute :reason, :string do
          allow_nil? true
          public? true
        end

        timestamps()
      end

      relationships do
        # Keyed by the BLOB row, exactly like the grants table: reconcile
        # creates requests with the grant subject id (`blob.id`), never
        # the #{inspect(resource)} id.
        belongs_to :blob, #{inspect(blob_resource)} do
          source_attribute :#{subject_id_attr}
          allow_nil? false
          public? true
        end

        belongs_to :user, #{inspect(user_resource)} do
          allow_nil? false
          public? true
          description "The principal who should end up with a grant."
        end

        belongs_to :requested_by, #{inspect(user_resource)} do
          allow_nil? true
          public? true
          description "The actor whose action triggered the request. May be nil."
        end

        belongs_to :fulfilled_by, #{inspect(user_resource)} do
          allow_nil? true
          public? true
          description "The actor who fulfilled the request. Nil while pending."
        end
      end

      actions do
        defaults [:read, :destroy, update: [:fulfilled_at, :fulfilled_by_id]]

        create :create do
          primary? true
          accept [:#{subject_id_attr}, :user_id, :requested_by_id, :requested_at, :reason]
        end
      end

      identities do
        # Prevents duplicate pending requests for the same (subject, target) pair.
        # The :where clause makes the identity partial — fulfilled rows can coexist.
        identity :unique_pending, [:#{subject_id_attr}, :user_id],
          where: expr(is_nil(fulfilled_at))
      end

      # AshEnvelope's `GrantRequests` APIs default to `authorize?: true`,
      # so this resource MUST define policies. The baseline below covers
      # the common patterns; tighten or expand to fit your threat model.
      #
      # Reconciliation (`AshEnvelope.Reconcile.Runner`) bypasses policies
      # via `authorize?: false` when revoking pending rows for principals
      # who lost access, so the system path is not subject to these.
      policies do
        # Read: target principals can see requests addressed to them;
        # admins can see all. Requesters can see what they triggered.
        policy action_type(:read) do
          authorize_if expr(user_id == ^actor(:id))
          authorize_if expr(requested_by_id == ^actor(:id))
          # authorize_if actor_attribute_equals(:role, :admin)
        end

        # Create: typical flow is "an integration creates a request when
        # reconciliation can't grant directly." If your application
        # exposes this directly to end users, gate it tighter.
        # policy action_type(:create) do
        #   authorize_if always()
        # end

        # Update: the row's `fulfilled_at`/`fulfilled_by_id` are set by
        # `GrantRequests.fulfill/6`. Allow the fulfilling actor to flip
        # them; uncomment after deciding who may fulfill.
        # policy action_type(:update) do
        #   authorize_if ...
        # end

        # Destroy: typically a target who decides they no longer want
        # the request, or an admin.
        policy action_type(:destroy) do
          authorize_if expr(user_id == ^actor(:id))
          authorize_if expr(requested_by_id == ^actor(:id))
          # authorize_if actor_attribute_equals(:role, :admin)
        end
      end
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 2. ADD MIGRATION                                           │
    └─────────────────────────────────────────────────────────────┘

    Run: mix ecto.gen.migration add_#{requests_table}

    Then paste:

    # ⚠ VERIFY TABLE NAMES — the `references(...)` targets below are
    # inferred from module names by naive pluralization. Check that
    # "#{blob_table}" and "#{user_table}" match the actual tables of
    # #{inspect(blob_resource)} and #{inspect(user_resource)} before running.

    def change do
      create table(:#{requests_table}, primary_key: false) do
        add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true

        # References the BLOB table — the same subject id the grants
        # table uses.
        add :#{subject_id_attr},
            references(:#{blob_table}, type: :uuid, on_delete: :delete_all),
            null: false

        add :user_id,
            references(:#{user_table}, type: :uuid, on_delete: :delete_all),
            null: false

        add :requested_by_id,
            references(:#{user_table}, type: :uuid, on_delete: :nilify_all),
            null: true

        add :fulfilled_by_id,
            references(:#{user_table}, type: :uuid, on_delete: :nilify_all),
            null: true

        add :requested_at, :utc_datetime_usec, null: false
        add :fulfilled_at, :utc_datetime_usec, null: true
        add :reason, :text, null: true

        timestamps(type: :utc_datetime_usec)
      end

      # Partial unique index: only one *pending* request per (subject, target).
      create unique_index(
               :#{requests_table},
               [:#{subject_id_attr}, :user_id],
               where: "fulfilled_at IS NULL",
               name: :unique_pending_grant_request
             )

      create index(:#{requests_table}, [:user_id])
      create index(:#{requests_table}, [:#{subject_id_attr}])
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 3. REGISTER IN DOMAIN                                      │
    └─────────────────────────────────────────────────────────────┘

    In #{inspect(domain)}, add:

    resource #{inspect(requests_resource)}

    ┌─────────────────────────────────────────────────────────────┐
    │ 4. CONFIG STRUCTS                                          │
    └─────────────────────────────────────────────────────────────┘

    Build the configs once (e.g. in a module attribute):

    @requests_config %AshEnvelope.GrantRequests.Config{
      resource: #{inspect(requests_resource)},
      subject_id_attribute: :#{subject_id_attr}
    }

    @grants_config %AshEnvelope.KeyGrants.Config{
      resource: #{inspect(grants_resource)},
      subject_id_attribute: :#{subject_id_attr},
      actor_public_key_attribute: :encryption_public_key,
      actor_private_key_attribute: :encryption_private_key
    }

    ┌─────────────────────────────────────────────────────────────┐
    │ 5. FULFILLMENT — pick a hook style                         │
    └─────────────────────────────────────────────────────────────┘

    a) On every authenticated request (cheap; no DB writes if no
       fulfillable requests for this actor):

    def call(conn, _opts) do
      actor = conn.assigns.current_user
      _ = AshEnvelope.GrantRequests.fulfill_outstanding(
        @requests_config, @grants_config, actor, #{inspect(domain)},
        &load_target/1
      )
      conn
    end

    defp load_target(user_id) do
      Ash.get(#{inspect(user_resource)}, user_id,
        authorize?: false,
        load: [:encryption_public_key]
      )
    end

    b) Admin panel listing pending requests the actor can fulfill:

    def list_pending(actor) do
      AshEnvelope.GrantRequests.list_fulfillable_for(
        @requests_config, @grants_config, actor, #{inspect(domain)}
      )
    end

    def fulfill(actor, request, target) do
      AshEnvelope.GrantRequests.fulfill(
        @requests_config, @grants_config, request, actor, target,
        #{inspect(domain)}
      )
    end

    ══════════════════════════════════════════════════════════════════
    Setup complete! Run your migration and you're ready to go.
    ══════════════════════════════════════════════════════════════════
    """)
  end

  defp infer_blob_resource(nil, resource), do: Module.concat([inspect(resource) <> "Blob"])
  defp infer_blob_resource(blob_str, _resource), do: Igniter.Project.Module.parse(blob_str)

  defp infer_table_name(resource) do
    resource
    |> Module.split()
    |> List.last()
    |> Macro.underscore()
    |> Kernel.<>("s")
  end

  defp infer_repo(nil, domain) do
    domain
    |> Module.split()
    |> Enum.take(1)
    |> Kernel.++(["Repo"])
    |> Module.concat()
  end

  defp infer_repo(repo_str, _domain) do
    Igniter.Project.Module.parse(repo_str)
  end

  defp requests_resource_path(requests_resource) do
    requests_resource
    |> Module.split()
    |> Enum.map(&Macro.underscore/1)
    |> then(fn parts -> "lib/#{Enum.join(parts, "/")}.ex" end)
  end
end
