
@{
  Name = "installation-tokens/audit-events-read"
  Path = "/installation-tokens/entities/audit-events/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "installation-tokens:read"
  Description = "Retrieve installation token audit events"
  Parameters = @(
    @{
      Dynamic = "EventIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "One or more event identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "api.auditEventDetailsResponseV1"
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}
