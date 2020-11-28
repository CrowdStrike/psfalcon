@{
  Name = "fwmgr/get-policy-containers"
  Path = "/fwmgr/entities/policies/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "Get policy container entities by policy ID"
  Parameters = @(
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more policy identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.api.PolicyContainersResponse"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}