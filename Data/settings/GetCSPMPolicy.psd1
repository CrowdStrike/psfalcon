@{
  Name = "settings/GetCSPMPolicy"
  Method = "get"
  Path = "/settings/entities/policy-details/v1"
  Description = "Given a policy ID, returns detailed policy information."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:read"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\d{1,}"
      Position = 1
      Description = "One or more policy identifiers"
    }
  )
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    default = "registration.PolicyResponseV1"
  }
}
