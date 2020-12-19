@{
  Name = "policy/createPreventionPolicies"
  Path = "/policy/entities/prevention/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "prevention-policies:write"
  Description = "Create Prevention Policies"
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
    @{
      Dynamic = "Settings"
      Name = "settings"
      Type = "array"
      In = @( "body" )
      Parent = "resources"
      Description = "An array of hashtables defining policy settings"
    }
  )
  Responses = @{
    201 = "responses.PreventionPoliciesV1"
    400 = "responses.PreventionPoliciesV1"
    403 = "msa.ErrorsOnly"
    404 = "responses.PreventionPoliciesV1"
    429 = "msa.ReplyMetaOnly"
    500 = "responses.PreventionPoliciesV1"
  }
}