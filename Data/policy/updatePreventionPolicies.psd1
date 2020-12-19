@{
  Name = "policy/updatePreventionPolicies"
  Path = "/policy/entities/prevention/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "prevention-policies:write"
  Description = "Update Prevention Policies by specifying the ID of the policy and details to update"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Pattern = "\w{32}"
      Description = "The id of the policy to update"
      Position = 1
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "The new name to assign to the policy"
      Position = 2
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Description = "The new description to assign to the policy"
      Position = 3
    }
    @{
      Dynamic = "Settings"
      Name = "settings"
      Type = "array"
      In = @( "body" )
      Parent = "resources"
      Description = "An array of hashtables defining policy settings"
      Position = 4
    }
  )
  Responses = @{
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "responses.PreventionPoliciesV1"
  }
}