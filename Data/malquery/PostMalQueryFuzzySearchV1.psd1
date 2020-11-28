@{
  Name = "malquery/PostMalQueryFuzzySearchV1"
  Path = "/malquery/combined/fuzzy-search/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "malquery:write"
  Description = "Search MalQuery quickly but with more potential for false positives."
  Parameters = @(
    @{
      Dynamic = "Fuzzy"
      Type = "switch"
      Required = $true
      Description = "Perform a fuzzy search"
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
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "body" )
      Parent = "options"
      Required = $false
      Description = "Maximum number of results per request"
      Position = $null
    }
    @{
      Dynamic = "PatternType"
      Name = "type"
      Type = "string"
      In = @( "body" )
      Parent = "patterns"
      Required = $true
      Enum = @(
        "hex"
        "ascii"
        "wide"
      )
      Description = "Pattern type"
      Position = $null
    }
    @{
      Dynamic = "PatternValue"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Parent = "patterns"
      Required = $true
      Description = "Pattern value"
      Position = $null
    }
  )
  Responses = @{
    200 = "malquery.FuzzySearchResponse"
    400 = "malquery.FuzzySearchResponse"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "malquery.FuzzySearchResponse"
  }
}