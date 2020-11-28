@{
  Name = "fwmgr/update-policy-container"
  Path = "/fwmgr/entities/policies/v1"
  Method = "PUT"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Update an identified policy container"
  Parameters = @(
    @{
      Dynamic = "DefaultInbound"
      Name = "default_inbound"
      Type = "string"
      In = @( "body" )
      Enum = @(
        "ALLOW"
        "DENY"
      )
      Required = $false
      Description = "Default action for inbound traffic"
      Position = $null
    }
    @{
      Dynamic = "DefaultOutbound"
      Name = "default_outbound"
      Type = "string"
      In = @( "body" )
      Enum = @(
        "ALLOW"
        "DENY"
      )
      Required = $false
      Description = "Default action for outbound traffic"
      Position = $null
    }
    @{
      Dynamic = "Enforce"
      Name = "enforce"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Enforce this policy's rules and override the firewall settings on each assigned host"
      Position = $null
    }
    @{
      Dynamic = "IsDefaultPolicy"
      Name = "is_default_policy"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Set as default policy"
      Position = $null
    }
    @{
      Dynamic = "PlatformId"
      Name = "platform_id"
      Type = "string"
      In = @( "body" )
      Enum = @(
        "0"
      )
      Required = $true
      Description = "Platform identifier"
      Position = $null
    }
    @{
      Dynamic = "PolicyId"
      Name = "policy_id"
      Type = "string"
      In = @( "body" )
      Required = $true
      Description = "Policy identifier to update"
      Position = $null
    }
    @{
      Dynamic = "GroupIds"
      Name = "rule_group_ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "One or more rule group identifiers"
      Position = $null
    }
    @{
      Dynamic = "MonitorMode"
      Name = "test_mode"
      Type = "bool"
      In = @( "body" )
      Required = $false
      Description = "Override all block rules in this policy and turn on monitoring"
      Position = $null
    }
    @{
      Dynamic = "Tracking"
      Name = "tracking"
      Type = "string"
      In = @( "body" )
      Required = $false
      Description = "Tracking identifier"
      Position = $null
    }
  )
  Responses = @{
    200 = "fwmgr.msa.ReplyMetaOnly"
    201 = "fwmgr.msa.ReplyMetaOnly"
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}