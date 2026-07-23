defmodule AshEnvelope.GrantRequests.Config do
  @moduledoc """
  Configuration for a grant requests table.

  A grant request is a "please grant me access" row created when an
  authorization-changing event happens but the actor at the time can't issue
  the grant themselves (typically because they don't hold a grant on the
  subject and therefore can't unwrap the DEK to re-wrap it for the new
  recipient). Any later actor who *does* hold the grant can fulfill the
  request — see `AshEnvelope.GrantRequests`.

  This config struct mirrors `AshEnvelope.KeyGrants.Config`. It describes
  how to read and write rows in an Ash resource that stores pending grant
  requests.

  ## Fields

  - `:resource` — the Ash resource module backing the grant requests table.
  - `:subject_id_attribute` — name of the FK attribute pointing at the
    encrypted subject. Should match the corresponding `KeyGrants.Config`.
  - `:target_principal_id_attribute` — FK attribute pointing at the
    user/principal who *should* end up with a grant. Defaults to `:user_id`.
  - `:requested_by_attribute` — FK attribute pointing at the actor whose
    action triggered the request. Defaults to `:requested_by_id`. May be
    nil on the row if no actor was available.
  - `:requested_at_attribute` — timestamp the request was created.
    Defaults to `:requested_at`. Set automatically on create.
  - `:fulfilled_at_attribute` — timestamp the request was fulfilled.
    Defaults to `:fulfilled_at`. `nil` for pending rows; set when fulfilled.
  - `:fulfilled_by_attribute` — FK attribute pointing at the actor who
    fulfilled the request. Defaults to `:fulfilled_by_id`. `nil` while
    pending.
  - `:reason_attribute` — optional free-text attribute for human-readable
    context (e.g. "added to org X"). Defaults to `:reason`. Optional.
  - `:authorize?` — whether Ash policy authorization is applied to grant
    request operations. Defaults to `true`. Set to `false` only on trusted
    system-side paths (e.g. reconciliation, integration tests without
    policies). When `true`, the grant-requests resource must define Ash
    policies; `mix ash_envelope.gen.grant_requests` scaffolds a baseline
    set.
  """

  @enforce_keys [:resource, :subject_id_attribute]
  defstruct [
    :resource,
    :subject_id_attribute,
    target_principal_id_attribute: :user_id,
    requested_by_attribute: :requested_by_id,
    requested_at_attribute: :requested_at,
    fulfilled_at_attribute: :fulfilled_at,
    fulfilled_by_attribute: :fulfilled_by_id,
    reason_attribute: :reason,
    authorize?: true
  ]

  @type t :: %__MODULE__{
          resource: module(),
          subject_id_attribute: atom(),
          target_principal_id_attribute: atom(),
          requested_by_attribute: atom(),
          requested_at_attribute: atom(),
          fulfilled_at_attribute: atom(),
          fulfilled_by_attribute: atom(),
          reason_attribute: atom(),
          authorize?: boolean()
        }
end
