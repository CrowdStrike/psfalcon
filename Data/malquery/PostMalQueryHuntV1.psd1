@{
  Name = "malquery/PostMalQueryHuntV1"
  Path = "/malquery/queries/hunt/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "malquery:write"
  Description = "Schedule a YARA-based search for execution"
  Parameters = @(
    @{
      Dynamic = "Hunt"
      Type = "switch"
      Required = $true
      Description = "Schedule a YARA-based search"
      Position = $null
    }
    @{
      Dynamic = "YaraRule"
      Name = "yara_rule"
      Type = "string"
      In = @( "body" )
      Required = $true
      Description = "A YARA rule that defines your search"
      Position = $null
    }
    @{
      Dynamic = "FilterMeta"
      Name = "filter_meta"
      Type = "array"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Pattern = "(sha256|md5|type|size|first_seen|label|family)"
      Description = "Subset of metadata fields to include in the results"
      Position = $null
    }
    @{
      Dynamic = "FilterFileTypes"
      Name = "filter_filetypes"
      Type = "array"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Pattern = "(cdf|cdfv2|cjava|dalvik|doc|docx|elf32|elf64|email|html|hwp|java.arc|lnk|macho|pcap|pdf|pe32|pe64|perl|ppt|pptx|python|pythonc|rtf|swf|text|xls|xlsx)"
      Description = "File types to include with the results"
      Position = $null
    }
    @{
      Dynamic = "MinDate"
      Name = "min_date"
      Type = "string"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Pattern = "\d{4}/\d{2}/\d{2}"
      Description = "Limit results to files first seen after this date"
      Position = $null
    }
    @{
      Dynamic = "MaxDate"
      Name = "max_date"
      Type = "string"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Pattern = "\d{4}/\d{2}/\d{2}"
      Description = "Limit results to files first seen after this date"
      Position = $null
    }
    @{
      Dynamic = "MinSize"
      Name = "min_size"
      Type = "string"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Description = "Minimum file size specified in bytes or multiples of KB/MB/GB"
      Position = $null
    }
    @{
      Dynamic = "MaxSize"
      Name = "max_size"
      Type = "string"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Description = "Maximum file size specified in bytes or multiples of KB/MB/GB"
      Position = $null
    }
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    default = "malquery.ExternalQueryResponse"
  }
}