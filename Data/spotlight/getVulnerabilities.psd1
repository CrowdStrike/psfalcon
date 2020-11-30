@{
  Name = "spotlight/getVulnerabilities"
  Path = "/spotlight/entities/vulnerabilities/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "spotlight-vulnerabilities:read"
  Description = "Get details on vulnerabilities by providing one or more IDs"
  Parameters = @(
    @{
      Dynamic = "VulnerabilityIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more vulnerability identifiers"
      Position = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "domain.SPAPIVulnerabilitiesEntitiesResponseV2"
  }
}