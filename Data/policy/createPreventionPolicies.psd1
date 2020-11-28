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
      Required = $false
      Description = "Copy settings from an existing policy"
      Pattern = "\w{32}"
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "Policy description"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "body" )
      Parent = "resources"
      Required = $true
      Description = "Policy name"
      Position = $null
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
      Position = $null
    }
    @{
      Dynamic = "Settings"
      Name = "settings"
      Type = "array"
      In = @( "body" )
      Parent = "resources"
      Required = $false
      Description = "An array of hashtables defining policy settings"
      Position = $null
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