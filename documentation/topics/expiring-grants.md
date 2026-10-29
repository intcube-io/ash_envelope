# Expiring Grants

`AshEnvelope.KeyGrants` supports two kinds of time-bounded access on the same grants table:

- **Time-bounded user grants** — a regular user grant with an `expires_at` deadline. Reads stop succeeding past the deadline; a TTL purge eventually removes the row. Useful for guest links, trial access, time-boxed audits, break-glass admin grants.
- **Ephemeral worker grants** — a row with no `user_id`, carrying the DEK sealed directly under an operator-managed seal key (`AshEnvelope.SealKey`, AAD = subject id). Lets deferred Oban analyzers decrypt without a user actor in scope.

Both share the same `expires_at` column and the same cron-purge query. Choose whichever your use case fits.

## Wiring

The generator emits the necessary columns and a baseline policy. Run:

```sh
mix ash_envelope.gen.key_grants MyApp.Blob \
  --grants-resource MyApp.BlobKeyGrant \
  --domain MyApp.Storage \
  --user-resource MyApp.User
```

The generated migration adds one nullable column (`expires_at`) and makes `user_id` nullable. The discriminator between row kinds is `user_id IS NULL` — no extra column, no CHECK constraint required. The `wrapped_dek` column carries two formats depending on row kind: an X25519 ECIES wrap for user grants, a `SealKey` ciphertext for ephemeral grants. Each resolve path knows which format to expect; the column polymorphism is invisible to callers.

The generated `:read` policy uses `expr(user_id == ^actor(:id))`. Because `NULL == anything` is `false` in SQL, this **implicitly excludes ephemeral rows** from user-facing reads — no separate guard needed. Worker reads go through `KeyGrants.resolve_ephemeral/3` with `authorize?: false`, invoked from the BlobIO manager.

## Time-bounded user grants

Pass `expires_at:` to `create_for_actor/6`:

```elixir
share_until = DateTime.add(DateTime.utc_now(), 24, :hour)

AshEnvelope.KeyGrants.create_for_actor(
  grants_config,
  document.id,
  dek,
  alice,
  MyApp.Storage,
  expires_at: share_until
)
```

`resolve_for_actor/4` rejects expired rows as `:not_found` — past the deadline, the grant logically does not exist. The physical row sticks around until the cron purges it.

### Interaction with reconcile

Reconcile's `grant_exists?/3` doesn't filter by `expires_at` today. The flow when a time-bounded grant expires:

1. Cron purges the row (`expires_at < now()` matches).
2. Next reconcile pass sees no grant for that (subject, principal) pair.
3. The `:read` policy on the encrypted resource decides whether to re-issue:
   - If the policy still authorizes Alice (e.g. she's a member of the project that owns the document), reconcile issues a **new permanent grant**.
   - If the policy no longer authorizes (e.g. her trial ended via `expr(now() < ^trial_end)`), no grant is issued.

**The policy is the access-control truth; `expires_at` is a grant-lifecycle convenience.** If you want a user to lose access permanently after some time, encode the time-bound in the read policy. `expires_at` alone just says "this grant should be revisited then" — the answer depends on the policy at that moment.

`mix ash_envelope.gen.key_grants` scaffolds this in its "4b. Policies on the encrypted resource" section, with three labeled patterns (trial-bounded, subscription-bounded, membership-bounded) to adapt to your schema.

## Ephemeral worker grants

The motivating use case: deferred Oban analyzers (`AshStorage.Operations.run_analyzer/3`) build a `BlobContext` with `actor: nil`. The `KeyGrants` BlobIO manager has no user actor to unwrap with, so the analyzer can't decrypt the source blob.

The fix: at attach time, alongside the user grant, the manager also creates an ephemeral grant row with:

- `user_id = NULL` (no principal — this is a worker-pathway capability)
- `wrapped_dek` — the DEK **sealed directly** under the env seal key with AAD = subject id (`AshEnvelope.SealKey`). No intermediate keypair: the seal key is symmetric and the worker pathway is entirely inside the trust domain (the same app code does the wrap at attach and the unwrap in the worker), so the X25519 wrap used for user grants would be overhead.
- `expires_at = now + ttl_seconds`

The Oban analyzer worker comes in with `actor: nil`. The manager's discriminator (`operation == :analyze` AND `analyzer != nil` AND `actor == nil` AND ephemeral attributes configured) routes the read through `KeyGrants.resolve_ephemeral/3`, which unseals the DEK in one step.

After `expires_at`, the cron purges the row. The worker pathway for that blob is dead until someone re-mints it.

### Seal key

Generate once:

```sh
openssl rand -base64 32
```

Wire in `runtime.exs`:

```elixir
config :ash_envelope,
  seal_key: System.fetch_env!("ASH_ENVELOPE_SEAL_KEY")
```

Accepted formats: a raw 32-byte binary or a base64-encoded string that decodes to 32 bytes.

### Threat model for the seal key

The seal key does not decrypt any blob by itself. It only opens the sealed DEKs of ephemeral grant rows that still exist. The blast radius of each compromise:

| What leaks | What attacker can decrypt |
| --- | --- |
| Env seal key, alone | Nothing — no rows to unseal without DB access |
| Env seal key + DB read | Only blobs with a live ephemeral grant row (currently in flight) |
| Env seal key + DB write | Same as above. AAD on the sealed DEK prevents row-relocation attacks. |
| A user's X25519 private key | The blobs that user has grants for. Independent of the worker pathway. |

Three properties combine to give this its shape:

1. **Per-attach row**, not per-application. Each sealed value opens exactly one blob's DEK.
2. **Sealed at rest** with AAD bound to the subject id. A sealed value lifted into a different row's column fails to unseal.
3. **TTL-bounded**. The lifetime of the worker capability for a blob is finite by design.

### TTL choice

`ephemeral_ttl_seconds` must exceed the worst-case analyzer pipeline duration **including retries**:

```
ttl_seconds  ≥  max_attempts × max_backoff_seconds  +  pipeline_slack
```

For stock AshOban defaults (`max_attempts: 20`, exponential backoff), 24h is comfortably safe. If your pipeline includes human-in-loop verification before all analyzers reach a terminal state, choose a longer TTL.

**Do not refresh `expires_at` on successful reads.** A read-triggered extension makes the TTL window unbounded and defeats the purpose. If your pipeline regularly exceeds the TTL, increase `ephemeral_ttl_seconds`, not per-read.

### Re-running analyzers after expiry

After the TTL window, the row is purged. A deferred analyzer trying to read for that blob fails with `{:error, :not_found}`. To re-run, someone must mint a fresh ephemeral row. Two paths depending on the authority you have:

**Admin with a user grant (recommended):**

```elixir
def rerun_analyzers(blob, admin) do
  with {:ok, _row} <-
         AshEnvelope.KeyGrants.renew_ephemeral_with_actor(
           grants_config,
           blob.id,
           admin,
           MyApp.Storage
         ) do
    AshOban.run_trigger(blob, :run_pending_analyzers)
    :ok
  end
end
```

`renew_ephemeral_with_actor/5` resolves the DEK via the admin's user grant **first**, then destroys-and-recreates the ephemeral row. If the admin can't unwrap, the existing row is not touched.

**Disaster recovery, no admin actor available:**

```elixir
def emergency_rerun(blob, backup_private_key) do
  with {:ok, dek} <- AshEnvelope.recover_dek(blob, backup_private_key),
       {:ok, _row} <-
         AshEnvelope.KeyGrants.renew_ephemeral(grants_config, blob.id, dek, MyApp.Storage) do
    AshOban.run_trigger(blob, :run_pending_analyzers)
    :ok
  end
end
```

The lower-level `renew_ephemeral/5` takes a raw DEK. It has no oracle to verify correctness — pass the wrong bytes and the legitimate row is destroyed plus replaced with one that decrypts to garbage (worker pathway breaks until someone calls it again with the right DEK; user reads via grants are unaffected throughout). Reserve `renew_ephemeral/5` for the backup-key path.

Backup-key use is the most sensitive operation in the system. Audit-log every call to `AshEnvelope.recover_dek/2` and treat unexpected uses as incidents.

### Rotating the seal key

The v1 rotation strategy is "drain via TTL":

1. Set the new key in your secrets store and redeploy. New writes use the new key; in-flight rows still need the old key to unseal.
2. Wait for the maximum `ephemeral_ttl_seconds` window so all rows sealed under the old key expire and get purged.
3. Retire the old key.

Multi-version seal-key lookup is deferred — the leading version byte in the sealed format is the rotation hatch when that becomes needed.

### Worker errors

`KeyGrants.resolve_ephemeral/3` returns:

- `{:error, :not_found}` — no ephemeral row for this subject (pipeline never ran, or already purged)
- `{:error, :expired}` — row exists but TTL elapsed; cron will sweep
- `{:error, :decryption_failed}` — sealed value can't be opened (seal key changed mid-flight, AAD mismatch, tampered bytes)
- `{:error, :corrupted_dek}` — stored wrapped DEK isn't valid base64

Treat all of these as **terminal** in the Oban analyzer worker — do not retry. The capability is gone; retrying won't bring it back. Log and dead-letter.

## TTL purge

Both kinds of expiring rows share one purge job. The generator emits the worker module skeleton; the query is:

```elixir
grants_resource
|> Ash.Query.filter(not is_nil(expires_at) and expires_at < ^DateTime.utc_now())
|> Ash.bulk_destroy(:destroy, %{}, domain: domain, authorize?: false)
```

Cheap, idempotent, every-minute cadence is fine. Run as an Oban cron.

## What this does NOT do

- It does not encrypt **analyzer output** (extracted markdown, JSON metadata). Those live in plaintext columns on the blob or the parent. If you need them encrypted, use `cloak_ecto` on the relevant attributes. The ephemeral-worker path is orthogonal.
- It does not provide **persistent service principals**. If you need a long-lived "indexer" actor that can decrypt many blobs over time, model it as a normal user-shaped principal with a key grant — not as an ephemeral row.
- It does not replace **backup-key escrow**. The `:backup_public_key` feature remains the disaster-recovery escape; ephemeral worker grants are a runtime convenience for a narrower use case.

## When the worker pathway is disabled

If you omit `:expires_at_attribute` (and `:ephemeral_ttl_seconds`) on the manager, no ephemeral rows are created at attach and the `unwrap_dek` discriminator never enters the ephemeral path. The manager behaves exactly as before, and deferred analyzers continue to fail with `:missing_principal` — restricting you to `analyze: :eager` analyzers that run with the user actor in scope during attach.
