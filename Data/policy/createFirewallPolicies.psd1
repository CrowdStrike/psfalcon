@{
  Name = "policy/createFirewallPolicies"
  Path = "/policy/entities/firewall/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Create Firewall Policies"
  Parameters = @(
    @{
      Dynamic = "CloneId"
      Name = "clone_id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "Copy settings from an existing policy"
      Pattern = "\w{32}"
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "Policy description"
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "Policy name"
    }
    @{
      Dynamic = "PlatformName"
      Name = "platform_name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Enum = @(
        "Windows"
        "Mac"
        "Linux"
      )
      Description = "Platform name"
    }
  )
  Responses = @{
    201 = "responses.FirewallPoliciesV1"
    400 = "responses.FirewallPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.FirewallPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.FirewallPoliciesV1"
  }
}