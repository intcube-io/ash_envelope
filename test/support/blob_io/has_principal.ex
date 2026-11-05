defmodule AshEnvelope.Test.BlobIO.HasPrincipal do
  # Create-side check: the row being inserted carries a principal
  # (`user_id` is set). An integrator hardening that says "application
  # code may only ever create user grants; principal-less ephemeral rows
  # are system-side". Used by `AshEnvelope.Test.BlobIO.PoliciedGrant`.
  @moduledoc false
  use Ash.Policy.SimpleCheck

  @impl true
  def describe(_opts), do: "the new grant row carries a principal (user_id set)"

  @impl true
  def match?(_actor, %{subject: %Ash.Changeset{} = changeset}, _opts) do
    not is_nil(Ash.Changeset.get_attribute(changeset, :user_id))
  end

  def match?(_actor, _context, _opts), do: false
end
