@{
  Name = "falconx/Submit"
  Path = "/falconx/entities/submissions/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "falconx-sandbox:write"
  Description = "Submit an uploaded file or a URL for sandbox analysis"
  Parameters = @(
    @{
      Dynamic = "EnvironmentId"
      Name = "environment_id"
      Type = "string"
      In = @( "body" )
      Enum = @(
        "Android"
        "Ubuntu16_x64"
        "Win7_x64"
        "Win7_x86"
        "Win10_x64"
      )
      Parent = "sandbox"
      Required = $true
      Description = "Specific environment to use for analysis"
      Position = 1
    }
    @{
      Dynamic = "Sha256"
      Name = "sha256"
      Type = "string"
      In = @( "body" )
      Pattern = "\w{64}"
      Parent = "sandbox"
      Required = $false
      Description = "SHA256 hash value of the sample to analyze"
      Position = $null
    }
    @{
      Dynamic = "Url"
      Name = "url"
      Type = "string"
      In = @( "body" )
      Parent = "sandbox"
      Required = $false
      Description = "A web page or file URL"
      Position = $null
    }
    @{
      Dynamic = "SubmitName"
      Name = "submit_name"
      Type = "string"
      In = @( "body" )
      Parent = "sandbox"
      Required = $false
      Description = "A name for the submission file"
      Position = $null
    }
    @{
      Dynamic = "UserTags"
      Name = "user_tags"
      Type = "array"
      In = @( "body" )
      Required = $false
      Description = "Tags to categorize the submission"
      Position = $null
    }
    @{
      Dynamic = "CommandLine"
      Name = "command_line"
      Type = "string"
      In = @( "body" )
      Min = 1
      Max = 2048
      Parent = "sandbox"
      Required = $false
      Description = "Command line script passed to the submitted file at runtime"
      Position = $null
    }
    @{
      Dynamic = "ActionScript"
      Name = "action_script"
      Type = "string"
      In = @( "body" )
      Enum = @(
        "default"
        "default_maxantievasion"
        "default_randomfiles"
        "default_randomtheme"
        "default_openie"
      )
      Parent = "sandbox"
      Required = $false
      Description = "Runtime script for sandbox analysis"
      Position = $null
    }
    
    @{
      Dynamic = "DocumentPassword"
      Name = "document_password"
      Type = "string"
      In = @( "body" )
      Min = 1
      Max = 32
      Parent = "sandbox"
      Required = $false
      Description = "Auto-filled for Adobe or Office files that prompt for a password"
      Position = $null
    }
    @{
      Dynamic = "EnableTor"
      Name = "enable_tor"
      Type = "bool"
      In = @( "body" )
      Parent = "sandbox"
      Required = $false
      Description = "Route traffic via TOR"
      Position = $null
    }
    @{
      Dynamic = "SystemDate"
      Name = "system_date"
      Type = "string"
      In = @( "body" )
      Parent = "sandbox"
      Pattern = "\d{4}-\d{2}-\d{2}"
      Required = $false
      Description = "A custom date to use in the sandbox environment"
      Position = $null
    }
    @{
      Dynamic = "SystemTime"
      Name = "system_time"
      Type = "string"
      In = @( "body" )
      Parent = "sandbox"
      Pattern = "\d{2}:\d{2}"
      Required = $false
      Description = "A custom time to use in the sandbox environment"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    default = "falconx.SubmissionV1Response"
  }
}