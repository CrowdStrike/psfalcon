@{
  Name = "cloud-connect-gcp/CreateCSPMGCPAccount"
  Path = "/cloud-connect-gcp/entities/account/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "d4c-registration:write"
  Description = "Creates a new GCP account and generates a script to grant access to the Falcon platform"
  Parameters = @(
    @{
      Dynamic = "ParentId"
      Name = "parent_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "GCP parent identifier"
    }
  )
  Responses = @{
    201 = "registration.GCPAccountResponseV1"
    207 = "registration.GCPAccountResponseV1"
    400 = "registration.GCPAccountResponseV1"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "registration.GCPAccountResponseV1"
  }
}