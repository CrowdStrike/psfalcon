@{
  Name = "policy/setFirewallPoliciesPrecedence"
  Path = "/policy/entities/firewall-precedence/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Sets the precedence of Firewall Policies based on the order of IDs specified in the request. The first ID specified will have the highest precedence and the last ID specified will have the lowest. You must specify all non-Default Policies for a platform when updating precedence"
  Parameters = @(
    @{
      Dynamic = "PlatformName"
      Name = "platform_name"
      Type = "string"
      In = @( "body" )
      Required = $true
      Enum = @(
        "Windows"
        "Mac"
        "Linux"
      )
      Description = "Platform name"
      Position = 1
    }
    @{
      Dynamic = "PolicyIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "All of the policy identifiers for the specified platform"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "msa.QueryResponse"
  }
}