defmodule AshEnvelope.Test.Reconcile.Domain do
  @moduledoc false
  use Ash.Domain

  resources do
    resource AshEnvelope.Test.Reconcile.User
    resource AshEnvelope.Test.Reconcile.Document
    resource AshEnvelope.Test.Reconcile.DocumentWithAffects
    resource AshEnvelope.Test.Reconcile.Membership
    resource AshEnvelope.Test.Reconcile.AffectingMembership
    resource AshEnvelope.Test.Reconcile.Grant
    resource AshEnvelope.Test.Reconcile.GrantRequest
  end
end
