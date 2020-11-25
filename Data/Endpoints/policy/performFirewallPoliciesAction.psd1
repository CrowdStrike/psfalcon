@{
  Name = "policy/performFirewallPoliciesAction"
  Path = "/policy/entities/firewall-actions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Perform actions on Firewall Policies"
  Parameters = @(
    @{
      Dynamic = "ActionName"
      Name = "action_name"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "add-host-group"
        "disable"
        "enable"
        "remove-host-group"
      )
      Description = "Action to perform"
      Position = $null
    }
    @{
      Dynamic = "PolicyId"
      Name = "ids"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{32}"
      Required = $true
      Description = "Policy identifier"
      Position = $null
    }
    @{
      Dynamic = "GroupId"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Parent = "action_parameters"
      Pattern = "\w{32}"
      Required = $false
      Description = "Host Group identifier used when adding or removing host groups"
      Position = $null
    }
  )
  Responses = @{
    200 = "responses.FirewallPoliciesV1"
    400 = "responses.FirewallPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.FirewallPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.FirewallPoliciesV1"
  }
}