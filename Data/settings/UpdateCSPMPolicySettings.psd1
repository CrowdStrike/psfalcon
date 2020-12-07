@{
  Name = "settings/UpdateCSPMPolicySettings"
  Method = "patch"
  Path = "/settings/entities/policy/v1"
  Description = "Updates a policy setting - can be used to override policy severity or to disable a policy entirely."
  Headers = @{
    ContentType = "application/json"
    Accept = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "policy_id"
      Type = "int"
      Parent = "resources"
      In = @( "body" )
      Required = $true
      Position = 1
      Description = $null
    }
    @{
      Dynamic = "Enabled"
      Name = "enabled"
      Type = "bool"
      Parent = "resources"
      In = @( "body" )
      Required = $false
      Position = 2
      Description = $null
    }
    @{
      Dynamic = "Severity"
      Name = "severity"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Enum = @(
        "high"
        "medium"
        "informational"
      )
      Required = $false
      Position = 3
      Description = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    default = "registration.PolicySettingsResponseV1"
    429 = "msa.ReplyMetaOnly"
    }
}
