@{
  Name = "intel/GetLatestIntelRuleFile"
  Path = "/intel/entities/rules-latest-files/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/zip"
  }
  Permission = "falconx-rules:read"
  Description = "Download the latest threat intelligence ruleset zip file"
  Parameters = @(
    @{
      Dynamic = "Type"
      Name = "type"
      Type = "string"
      In = @( "query" )
      Required = $true
      Enum = @(
        "snort-suricata-master"
        "snort-suricata-update"
        "snort-suricata-changelog"
        "yara-master"
        "yara-update"
        "yara-changelog"
        "common-event-format"
        "netwitness"
      )
      Description = "Rule news report type"
      Position = 1
    }
    @{
      Dynamic = "Path"
      Name = ""
      Type = "string"
      In = @( "outfile" )
      Required = $true
      Pattern = "\.zip$"
      Description = "Destination Path"
      Position = 2
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