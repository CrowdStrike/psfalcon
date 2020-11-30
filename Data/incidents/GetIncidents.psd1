@{
  Name = "incidents/GetIncidents"
  Path = "/incidents/entities/incidents/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "incidents:read"
  Description = "List detailed information about Incidents"
  Parameters = @(
    @{
      Dynamic = "IncidentIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Max = 500
      Description = "One or more Incident identifiers"
      Position = $null
    }
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    default = "api.MsaExternalIncidentResponse"
  }
}