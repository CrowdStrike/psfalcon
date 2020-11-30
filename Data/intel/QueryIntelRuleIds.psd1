@{
  Name = "intel/QueryIntelRuleIds"
  Path = "/intel/queries/rules/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-rules:read"
  Description = "Search for rule IDs that match provided filter criteria."
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
      Description = "The rule news report type"
      Position = 1
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "Search by rule title."
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "Substring match on description field."
      Position = $null
    }
    @{
      Dynamic = "Tags"
      Name = "tags"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "Search for rule tags."
      Position = $null
    }
    @{
      Dynamic = "MinCreatedDate"
      Name = "min_created_date"
      Type = "int"
      In = @( "query" )
      Required = $false
      Description = "Filter results to those created on or after a certain date."
      Position = $null
    }
    @{
      Dynamic = "MaxCreatedDate"
      Name = "max_created_date"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Filter results to those created on or before a certain date."
      Position = $null
    }
    @{
      Dynamic = "Query"
      Name = "q"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Position = $null
    }
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 10000
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    400 = "msa.ErrorsOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
    default = "msa.QueryResponse"
  }
}