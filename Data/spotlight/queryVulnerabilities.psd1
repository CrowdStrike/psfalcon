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
      Description = "A pagination token used with the Limit parameter to manage pagination of results"
    }
    @{
      Dynamic = "Limit"
      Name = "limit"
      Type = "int"
      In = @( "query" )
      Min = 1
      Max = 400
      Description = "Maximum number of results per request"
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.SPAPIQueryVulnerabilitiesResponse"
  }
}