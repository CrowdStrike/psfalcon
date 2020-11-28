@{
  Name = "intel/GetIntelRuleFile"
  Path = "/intel/entities/rules-files/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/zip"
  }
  Permission = "falconx-rules:read"
  Description = "Download a specific threat intelligence ruleset zip file"
  Parameters = @(
    @{
      Dynamic = "RuleId"
      Name = "id"
      Type = "int"
      In = @( "query" )
      Required = $true
      Description = "Rule set identifier"
      Position = $null
    }
    @{
      Dynamic = "Path"
      Name = ""
      Type = "string"
      In = @(
        "outfile"
      )
      Required = $true
      Pattern = "\.zip$"
      Description = "Destination Path"
      Position = $null
    }
  )
  Responses = @{
    200 = ""
    400 = "msa.ErrorsOnly"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
  }
}