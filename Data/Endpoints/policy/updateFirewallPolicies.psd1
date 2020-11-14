@{
  Name = "policy/updateFirewallPolicies"
  Path = "/policy/entities/firewall/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "firewall-management:write"
  Description = "Update Firewall Policies by specifying the ID of the policy and details to update"
  Parameters = @(
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new description to assign to the policy"
      Position = $null
    }
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "The id of the policy to update"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "The new name to assign to the policy"
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