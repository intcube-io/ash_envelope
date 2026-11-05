defmodule Mix.Tasks.AshEnvelope.Gen.KeyGrants do
  @moduledoc """
  Generates multi-recipient envelope encryption infrastructure.

  Creates instructions for:
  - A key grants Ash resource (stores per-user wrapped DEKs)
  - An Ecto migration for the grants table
  - User resource changes (X25519 public/private key attributes + auto-generation)
  - Encrypted resource changes (BlobIO encryption layer + `KeyGrants` key manager)
  - Domain registration
  - File controller route for encrypted serving
  - LiveView share/revoke UI handlers

  ## Usage

      mix ash_envelope.gen.key_grants MyApp.Document \\
        --grants-resource MyApp.FileKeyGrant \\
        --domain MyApp.Catalog \\
        --user-resource MyApp.User

  ## Options

  * `--grants-resource` - Module name for the key grants resource (required)
  * `--domain` - The Ash domain module (required)
  * `--user-resource` - The user/actor resource module (required)
  * `--blob-resource` - The `AshStorage.BlobResource` module the attachment
    stores into. Grants are keyed by the blob row, because that is the only
    id the `KeyGrants` BlobIO manager sees on every read path (default:
    inferred from the resource name, e.g. MyApp.Document -> MyApp.DocumentBlob)
  * `--file-id-attribute` - FK name on the grants table pointing at the blob
    row (default: `:blob_id`, matching `AshEnvelope.KeyGrants.Config`)
  * `--actor-public-key-attribute` - Attribute on actor holding their X25519
    public key (default: `:encryption_public_key`)
  * `--actor-private-key-attribute` - Attribute on actor holding their X25519
    private key (default: `:encryption_private_key`)
  * `--file-attribute` - Name of the file attribute on the resource (default: :file)
  * `--repo` - The Ecto repo module (default: inferred from domain)
  """

  use Igniter.Mix.Task

  @impl Igniter.Mix.Task
  def info(_argv, _parent) do
    %Igniter.Mix.Task.Info{
      positional: [:resource],
      schema: [
        grants_resource: :string,
        domain: :string,
        user_resource: :string,
        blob_resource: :string,
        file_id_attribute: :string,
        actor_public_key_attribute: :string,
        actor_private_key_attribute: :string,
        file_attribute: :string,
        repo: :string
      ],
      required: [:grants_resource, :domain, :user_resource]
    }
  end

  @impl Igniter.Mix.Task
  def igniter(igniter) do
    resource = Igniter.Project.Module.parse(igniter.args.positional.resource)
    grants_resource = Igniter.Project.Module.parse(igniter.args.options[:grants_resource])
    domain = Igniter.Project.Module.parse(igniter.args.options[:domain])
    user_resource = Igniter.Project.Module.parse(igniter.args.options[:user_resource])
    blob_resource = infer_blob_resource(igniter.args.options[:blob_resource], resource)

    # Grants are keyed by the blob row: `AshEnvelope.BlobIO.KeyManagers.KeyGrants`
    # resolves the subject id from `bctx.blob.id` (the owning record is not
    # on the BlobContext for proxy / analyzer / download reads), so the FK
    # must point at the blob table and defaults to the library-wide
    # `:blob_id` (see `AshEnvelope.KeyGrants.Config`).
    file_id_attr =
      if igniter.args.options[:file_id_attribute] do
        String.to_atom(igniter.args.options[:file_id_attribute])
      else
        :blob_id
      end

    actor_public_key_attr =
      String.to_atom(igniter.args.options[:actor_public_key_attribute] || "encryption_public_key")

    actor_private_key_attr =
      String.to_atom(
        igniter.args.options[:actor_private_key_attribute] || "encryption_private_key"
      )

    file_attr = String.to_atom(igniter.args.options[:file_attribute] || "file")
    repo = infer_repo(igniter.args.options[:repo], domain)
    table_name = infer_table_name(grants_resource)
    blob_table = infer_table_name(blob_resource)
    user_table = infer_table_name(user_resource)
    resource_rel_name = infer_relationship_name(resource)

    igniter
    |> Igniter.add_notice("""
    ══════════════════════════════════════════════════════════════════
    Multi-recipient Envelope Encryption Setup for #{inspect(resource)}
    ══════════════════════════════════════════════════════════════════

    ┌─────────────────────────────────────────────────────────────┐
    │ 1. CREATE THE KEY GRANTS RESOURCE                          │
    └─────────────────────────────────────────────────────────────┘

    Create the file: #{grants_resource_path(grants_resource)}

    defmodule #{inspect(grants_resource)} do
      use Ash.Resource,
        domain: #{inspect(domain)},
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer]

      postgres do
        table "#{table_name}"
        repo #{inspect(repo)}
      end

      attributes do
        uuid_primary_key :id

        attribute :wrapped_dek, :string do
          # User grants:        X25519-wrapped DEK (`AshEnvelope.wrap_dek/2`)
          # Ephemeral grants:   DEK sealed under `AshEnvelope.SealKey`
          # The row kind (user_id set vs null) tells the resolve path
          # which format to expect.
          allow_nil? false
          sensitive? true
          public? false
        end

        # Optional expiry column. Permanent user grants leave it nil.
        # Ephemeral worker grants always set it.
        attribute :expires_at, :utc_datetime_usec do
          allow_nil? true
          public? true
        end

        timestamps()
      end

      relationships do
        # Grants hang off the BLOB row, not off #{inspect(resource)}. The
        # `KeyGrants` BlobIO manager derives the subject id from
        # `bctx.blob.id` on every write and read — the owning record is
        # not on the BlobContext for proxy / analyzer / download reads —
        # so this FK must reference the blob table (see step 2) and the
        # reconcile block must map a record to its blob id (see step 4).
        belongs_to :blob, #{inspect(blob_resource)} do
          source_attribute :#{file_id_attr}
          allow_nil? false
          public? true
        end

        # Nullable so ephemeral worker rows (no principal) can coexist
        # with user grants in the same table.
        belongs_to :user, #{inspect(user_resource)} do
          allow_nil? true
          public? true
        end
      end

      actions do
        # The `defaults` are marked primary by Ash automatically;
        # `KeyGrants.resolve_for_actor/4` and `KeyGrants.revoke/3` rely
        # on the primary read/destroy actions.
        defaults [:read, :destroy]

        # `primary? true` is required — `KeyGrants.create_for_actor/6`
        # (and `share/6`) call `Ash.create/2`, which needs a primary
        # create action.
        create :create do
          primary? true
          accept [:wrapped_dek, :#{file_id_attr}, :user_id, :expires_at]
        end
      end

      # AshEnvelope's grant-mutating APIs default to `authorize?: true`,
      # so this resource MUST define policies. The baseline below covers
      # the common patterns; tighten or expand to fit your threat model.
      #
      # Reconciliation (`AshEnvelope.Reconcile.Runner`) passes
      # `authorize?: false` internally, so the system-side rewrap and
      # revoke paths are not subject to these policies — they only
      # apply to direct calls from your application code.
      policies do
        # Read: a principal can see grants where they are the user
        # AND the row hasn't expired.
        # Required for `AshEnvelope.KeyGrants.resolve_for_actor/4`.
        # `user_id == ^actor(:id)` implicitly excludes ephemeral rows
        # (`user_id IS NULL`), since `NULL == anything` is `false` in
        # SQL. Worker-side reads use `KeyGrants.resolve_ephemeral/3`,
        # which is invoked from the BlobIO manager with
        # `authorize?: false`.
        #
        # The `is_nil(expires_at) or expires_at > now()` clause is
        # defense in depth — `KeyGrants.resolve_for_actor/4` also
        # rejects expired rows at runtime via `check_not_expired/2`.
        # This filters direct reads (`Ash.read(MyApp.FileKeyGrant, …)`)
        # that bypass the resolve path.
        #
        # If you removed `expires_at_attribute` from the encryption
        # layer config (and the `expires_at` column with it), drop
        # the `is_nil/...` clause too.
        policy action_type(:read) do
          authorize_if expr(
                         user_id == ^actor(:id) and
                           (is_nil(expires_at) or expires_at > now())
                       )
        end

        # Create: the caller of `KeyGrants.share/5` re-wraps an existing
        # DEK for a target principal, so the actor's id and the new
        # row's user_id will differ. The integrator must decide who is
        # allowed to grant whom. Typical options (pick one):
        #
        # 1. Anyone who already holds a grant on the subject can share:
        #      policy action_type(:create) do
        #        authorize_if exists(
        #          #{inspect(grants_resource)},
        #          #{file_id_attr} == ^changeset(:#{file_id_attr}) and user_id == ^actor(:id)
        #        )
        #      end
        #
        # 2. Members of the same organisation can share:
        #      policy action_type(:create) do
        #        authorize_if relates_to_actor_via_org(...)  # your rule
        #      end
        #
        # 3. Only admins can grant (most restrictive):
        #      policy action_type(:create) do
        #        authorize_if actor_attribute_equals(:role, :admin)
        #      end
        #
        # The example below picks (1) but is commented out — uncomment
        # and tailor before relying on it in production.
        # policy action_type(:create) do
        #   authorize_if always()
        # end

        # Destroy: a principal can revoke their own grant (self-revoke).
        # Add an admin-revoke clause if your app needs it.
        policy action_type(:destroy) do
          authorize_if expr(user_id == ^actor(:id))
          # authorize_if actor_attribute_equals(:role, :admin)
        end
      end
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 2. ADD MIGRATION                                           │
    └─────────────────────────────────────────────────────────────┘

    Run: mix ecto.gen.migration add_#{table_name}

    Then paste:

    # ⚠ VERIFY TABLE NAMES — the `references(...)` targets below are
    # inferred from module names by naive pluralization. Check that
    # "#{blob_table}" and "#{user_table}" match the actual tables of
    # #{inspect(blob_resource)} and #{inspect(user_resource)} before running.

    def change do
      create table(:#{table_name}, primary_key: false) do
        add :id, :uuid, null: false, default: fragment("gen_random_uuid()"), primary_key: true
        add :wrapped_dek, :text, null: false

        # References the BLOB table: the subject id the KeyGrants manager
        # writes and reads is `blob.id`, never the owning record's id.
        add :#{file_id_attr},
            references(:#{blob_table}, type: :uuid, on_delete: :delete_all),
            null: false

        # Nullable so ephemeral worker rows (no principal) can coexist
        # with user grants. The discriminator `user_id IS NULL` tells
        # the resolve paths which row kind they're dealing with.
        add :user_id, references(:#{user_table}, type: :uuid), null: true

        # Optional expiry column. NULL for permanent user grants;
        # always set for ephemeral worker grants and time-bounded
        # user grants. See `AshEnvelope.KeyGrants` and the
        # `expiring-grants` topic for the threat model.
        add :expires_at, :utc_datetime_usec, null: true

        timestamps(type: :utc_datetime_usec)
      end

      # User grants are unique per (subject, user). Partial index so
      # ephemeral rows (user_id IS NULL) are not subject to this
      # uniqueness — they use the index below.
      create unique_index(
               :#{table_name},
               [:#{file_id_attr}, :user_id],
               where: "user_id IS NOT NULL"
             )

      # At most one ephemeral row per subject.
      create unique_index(
               :#{table_name},
               [:#{file_id_attr}],
               where: "user_id IS NULL",
               name: :#{table_name}_one_ephemeral_per_subject
             )

      # The TTL purge job filters on this column.
      create index(:#{table_name}, [:expires_at], where: "expires_at IS NOT NULL")
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 3. UPDATE THE USER RESOURCE                                │
    └─────────────────────────────────────────────────────────────┘

    ⚠ SECURITY (REQUIRED for production)

    The private key column MUST be encrypted at rest with a KEK held
    outside the application database. Otherwise any reader of the user
    table (DBA, backup leak, replica snapshot) can decrypt every record
    that principal has access to. AshEnvelope's threat model assumes
    this protection — see `documentation/topics/how-envelope-encryption-works.md`,
    section "Private-key custody".

    RECOMMENDED — use `AshCloak` (or `cloak`) for the private key:

        # mix.exs:
        # {:ash_cloak, "~> 0.1"}

        attribute :#{actor_public_key_attr}, :binary do
          allow_nil? true
          public? true
        end

        attribute :#{actor_private_key_attr}, AshCloak.Type.EncryptedBinary do
          allow_nil? true
          sensitive? true
          public? false
        end

    TEST-ONLY fallback (DO NOT USE IN PRODUCTION) — plain binary column:

        attribute :#{actor_private_key_attr}, :binary do
          allow_nil? true
          sensitive? true
          public? false
        end

    In the create action, generate an X25519 key pair on signup:

        change fn changeset, _ ->
          {public_key, private_key} = :crypto.generate_key(:ecdh, :x25519)

          changeset
          |> Ash.Changeset.force_change_attribute(:#{actor_public_key_attr}, public_key)
          |> Ash.Changeset.force_change_attribute(:#{actor_private_key_attr}, private_key)
        end

    ┌─────────────────────────────────────────────────────────────┐
    │ 4. UPDATE THE ENCRYPTED RESOURCE                           │
    └─────────────────────────────────────────────────────────────┘

    In #{inspect(resource)}, configure the BlobIO encryption layer with the
    `KeyGrants` key manager. `storage do` takes one `layer` entity per
    layer (there is no `layers [...]` list), and `metadata_key` is the
    stable identifier persisted in blob metadata — choose it once and
    never rename it, or existing blobs become unreadable.

    use Ash.Resource,
      domain: #{inspect(domain)},
      extensions: [AshStorage, AshEnvelope.Reconcile]

    storage do
      service {AshStorage.Service.S3, bucket: "private-blobs"}

      # Your AshStorage blob + attachment resources (both required by
      # the storage DSL). The blob resource is the one the grants table
      # references (see steps 1 and 2).
      blob_resource #{inspect(blob_resource)}
      attachment_resource #{inspect(resource)}Attachment

      layer {AshStorage.Layer.Encryption,
             key_manager:
               {AshEnvelope.BlobIO.KeyManagers.KeyGrants,
                grants_resource: #{inspect(grants_resource)},
                domain: #{inspect(domain)},
                actor_public_key_attribute: :#{actor_public_key_attr},
                actor_private_key_attribute: :#{actor_private_key_attr},
                subject_id_attribute: :#{file_id_attr},
                # Opt-in: time-bounded user grants AND per-attach
                # ephemeral worker grants for deferred analyzer reads.
                # Drop these two lines if you only want permanent user
                # grants and have no `:oban` analyzers. See the
                # `expiring-grants` topic for the threat model and TTL
                # guidance.
                expires_at_attribute: :expires_at,
                ephemeral_ttl_seconds: 86_400},
             proxy_base_url: "/storage"},
            metadata_key: "#{resource_rel_name}-vault"

      has_one_attached :#{file_attr}
    end

    reconcile do
      user_resource #{inspect(user_resource)}
      domain #{inspect(domain)}
      key_grants_resource #{inspect(grants_resource)}
      key_grants_subject_id_attribute :#{file_id_attr}
      actor_public_key_attribute :#{actor_public_key_attr}
      actor_private_key_attribute :#{actor_private_key_attr}

      # The KeyGrants manager keys grants by the BLOB id (`bctx.blob.id`),
      # so reconcile must derive the same id from a #{inspect(resource)}
      # record: walk the `:#{file_attr}` attachment to its `blob_id`.
      # Without these two lines reconcile looks grants up by the record
      # id, never finds the manager's rows, and re-issues (or queues
      # requests for) every pair on every pass. A record with no
      # attachment yet yields nil and is skipped.
      subject_load [:#{file_attr}]
      subject_id_for fn record -> record.#{file_attr} && record.#{file_attr}.blob_id end
    end

    Also add the inverse relationship on the BLOB resource
    (#{inspect(blob_resource)}), pinning `destination_attribute` to the
    grants FK so it still resolves when `--file-id-attribute` is not the
    Ash default for that resource:

    has_many :key_grants, #{inspect(grants_resource)} do
      destination_attribute :#{file_id_attr}
      public? true
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 4b. POLICIES ON THE ENCRYPTED RESOURCE                     │
    └─────────────────────────────────────────────────────────────┘

    ⚠ T20 — Time-bounded grant outlives policy intent

    When `:expires_at_attribute` is configured (see step 4 above),
    the `:read` policy on THIS resource is the access-control truth.
    Reconcile consults it to decide whether to re-issue a grant
    after the TTL cron purges an expired row — if the policy still
    authorizes the user, reconcile issues a NEW PERMANENT grant
    and your `expires_at` intent silently breaks.

    If you want "access ends at time X regardless of policy," encode
    the same time bound here. See `documentation/topics/expiring-grants.md`
    for the full explanation.

    Pick one of the patterns below (commented out — uncomment and
    tailor before relying on it in production):

    use Ash.Resource,
      domain: #{inspect(domain)},
      extensions: [AshStorage, AshEnvelope.Reconcile],
      authorizers: [Ash.Policy.Authorizer]

    policies do
      # Pattern 1 — trial-bounded: access ends when the actor's
      # trial period closes. The bound is on the actor.
      # policy action_type(:read) do
      #   authorize_if expr(now() < ^actor(:trial_end))
      # end

      # Pattern 2 — subscription-bounded: access ends when the
      # actor's active subscription expires. The bound is on a
      # related row.
      # policy action_type(:read) do
      #   authorize_if expr(
      #     exists(subscriptions,
      #       user_id == ^actor(:id) and active and now() < ends_at)
      #   )
      # end

      # Pattern 3 — membership-bounded: access ends when the
      # actor's membership in the owning org lapses (mirrors the
      # `test/support/reconcile/document.ex` fixture in the
      # ash_envelope repo).
      # policy action_type(:read) do
      #   authorize_if expr(
      #     exists(memberships,
      #       user_id == ^actor(:id) and
      #         (is_nil(until) or now() < until))
      #   )
      # end
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 5. REGISTER IN DOMAIN                                      │
    └─────────────────────────────────────────────────────────────┘

    In #{inspect(domain)}, add:

    resource #{inspect(grants_resource)}

    ┌─────────────────────────────────────────────────────────────┐
    │ 6. FILE PROXY ROUTE                                        │
    └─────────────────────────────────────────────────────────────┘

    Encrypted blobs are not directly servable — the BlobIO encryption
    layer requires going through `AshStorage.BlobIO.read/3` (or the
    proxy route an `:proxy_base_url` resolves to). Mount
    `AshStorage.Plug.Proxy` INSIDE your authenticated router scope
    and configure `:actor_assign` so the KeyGrants manager has a
    real principal to authorize against:

        scope "/storage", #{inspect(Module.concat(["MyAppWeb"]))} do
          # ⚠ OUTER AUTH (REQUIRED) — wire your auth pipeline first
          pipe_through [:browser, :require_authenticated_user]

          forward "/", AshStorage.Plug.Proxy,
            resource: #{inspect(resource)},
            attachment: :#{file_attr},
            access:
              {:signed,
               secret:
                 Application.compile_env(:my_app, :proxy_signing_secret)},
            actor_assign: :current_user,
            max_lifetime_seconds: 300
        end

    `:actor_assign` is load-bearing for the KeyGrants manager — the
    bearer alone is not authentication. See the "Serving encrypted
    blobs over HTTP" section of `how-envelope-encryption-works.md`
    for the full threat model + signing-secret rotation cadence.

    ┌─────────────────────────────────────────────────────────────┐
    │ 7. LIVEVIEW KEY MANAGEMENT (share/revoke)                  │
    └─────────────────────────────────────────────────────────────┘

    Use `AshEnvelope.KeyGrants` for share and revoke operations:

    # Build config once (e.g. in mount or a module attribute):
    @grants_config %AshEnvelope.KeyGrants.Config{
      resource: #{inspect(grants_resource)},
      subject_id_attribute: :#{file_id_attr},
      actor_public_key_attribute: :#{actor_public_key_attr},
      actor_private_key_attribute: :#{actor_private_key_attr}
    }

    # Share a file with another user (only needs the target's public key).
    # The grant subject is the BLOB id (`document.#{file_attr}.blob_id`), not
    # the #{inspect(resource)} id — same id the KeyGrants manager keys by.
    def handle_event("share", %{"blob_id" => blob_id, "target_user_id" => target_user_id}, socket) do
      actor = load_actor_with_keys(socket.assigns.current_user)
      target = load_actor_with_keys(target_user_id)

      case AshEnvelope.KeyGrants.share(@grants_config, blob_id, actor, target, #{inspect(domain)}) do
        :ok ->
          {:noreply, put_flash(socket, :info, "Access granted")}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Could not share: \#{inspect(reason)}")}
      end
    end

    # Revoke access. Fetch AND revoke as the current user so the
    # resource's policies apply — the read policy scopes which grants
    # the actor can even see, and the destroy policy decides whether
    # they may revoke. Never fetch with `authorize?: false` here: that
    # would let any authenticated user revoke any grant by id.
    def handle_event("revoke", %{"grant_id" => grant_id}, socket) do
      actor = socket.assigns.current_user

      with {:ok, grant} <-
             Ash.get(#{inspect(grants_resource)}, grant_id, actor: actor, authorize?: true),
           :ok <- AshEnvelope.KeyGrants.revoke(grant, #{inspect(domain)}, actor: actor) do
        {:noreply, put_flash(socket, :info, "Access revoked")}
      else
        {:error, _} -> {:noreply, put_flash(socket, :error, "Could not revoke")}
      end
    end

    # Load user with both X25519 keys:
    defp load_actor_with_keys(user_or_id) do
      id = if is_binary(user_or_id), do: user_or_id, else: user_or_id.id

      case Ash.get(#{inspect(user_resource)}, id,
             select: [:id, :#{actor_public_key_attr}, :#{actor_private_key_attr}]) do
        {:ok, user} -> user
        _ -> nil
      end
    end

    # List documents with grants preloaded (grants hang off the blob):
    defp list_documents(user) do
      actor = load_actor_with_keys(user)
      case Ash.read(#{inspect(resource)}, actor: actor, authorize?: true) do
        {:ok, docs} ->
          Ash.load!(docs, [#{file_attr}: [blob: [key_grants: [:user]]]], authorize?: false)

        {:error, _} ->
          []
      end
    end

    ┌─────────────────────────────────────────────────────────────┐
    │ 8. EXPIRY / EPHEMERAL — set the seal key + schedule purge  │
    └─────────────────────────────────────────────────────────────┘

    Skip this section if you removed `expires_at_attribute` (and
    `ephemeral_ttl_seconds`) from the key manager opts. Otherwise:

    1. Generate a 32-byte seal key once and store it in your secrets
       store:

         openssl rand -base64 32

    2. Wire it in `runtime.exs`:

         config :ash_envelope,
           seal_key: System.fetch_env!("ASH_ENVELOPE_SEAL_KEY")

       The seal key never decrypts a blob directly — it only opens
       the sealed DEK stored on each ephemeral grant row (AAD-bound to
       that row's subject id), and that DEK is what decrypts the blob.

    3. Schedule a TTL purge job. Both time-bounded user grants and
       ephemeral worker grants live in the same table, both surface
       via `expires_at`, and one cron handles both:

         defmodule MyApp.Storage.KeyGrantPurger do
           use Oban.Worker, queue: :default
           require Ash.Query

           @impl Oban.Worker
           def perform(_job) do
             now = DateTime.utc_now()

             #{inspect(grants_resource)}
             |> Ash.Query.filter(not is_nil(expires_at) and expires_at < ^now)
             |> Ash.bulk_destroy(:destroy, %{},
               domain: #{inspect(domain)},
               authorize?: false,
               return_errors?: true
             )

             :ok
           end
         end

         config :my_app, Oban,
           plugins: [
             {Oban.Plugins.Cron,
              crontab: [{"* * * * *", MyApp.Storage.KeyGrantPurger}]}
           ]

    4. Choose `ephemeral_ttl_seconds` (on the manager opts) larger
       than `max_attempts × max_backoff` of your analyzer trigger,
       plus pipeline slack. Default 86_400s (24h) is safe for stock
       AshOban defaults.

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

  defp infer_relationship_name(resource) do
    resource
    |> Module.split()
    |> List.last()
    |> Macro.underscore()
    |> String.to_atom()
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

  defp grants_resource_path(grants_resource) do
    grants_resource
    |> Module.split()
    |> Enum.map(&Macro.underscore/1)
    |> then(fn parts ->
      "lib/#{Enum.join(parts, "/")}.ex"
    end)
  end
end
