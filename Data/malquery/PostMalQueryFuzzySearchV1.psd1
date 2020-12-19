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
    }
    @{
      Dynamic = "PatternValue"
      Name = "value"
      Type = "string"
      In = @( "body" )
      Parent = "patterns"
      Required = $true
      Description = "Pattern value"
    }
    @{
      Dynamic = "FilterMeta"
      Name = "filter_meta"
      Type = "array"
      In = @( "body" )
      Parent = "options"
      Pattern = "(sha256|md5|type|size|first_seen|label|family)"
      Description = "Subset of metadata fields to include in the results"
    }
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "body" )
      Parent = "options"
      Description = "Maximum number of results per request"
    }
    @{
      Dynamic = "Fuzzy"
      Type = "switch"
      Required = $true
      Description = "Perform a fuzzy search"
    }
  )
  Responses = @{
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    default = "malquery.FuzzySearchResponse"
  }
}