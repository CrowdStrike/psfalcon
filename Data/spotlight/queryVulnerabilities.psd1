@{
  Name = "spotlight/queryVulnerabilities"
  Path = "/spotlight/queries/vulnerabilities/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "spotlight-vulnerabilities:read"
  Description = "Search for vulnerability identifiers"
  Parameters = @(
    @{
      Dynamic = "After"
      Name = "after"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "A pagination token used with the Limit parameter to manage pagination of results"
      Position = $null
    }
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Required = $false
      Min = 1
      Max = 400
      Description = "Maximum number of results per request"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.SPAPIQueryVulnerabilitiesResponse"
  }
}