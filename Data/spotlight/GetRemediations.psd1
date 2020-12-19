@{
  Name = "spotlight/GetRemediations"
  Path = "/spotlight/entities/remediations/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "spotlight-vulnerabilities:read"
  Description = "Get information about remediations"
  Parameters = @(
    @{
      Dynamic = "RemediationIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Pattern = "\w{32}"
      Required = $true
      Description = "Remediation identifiers"
    }
  )
}