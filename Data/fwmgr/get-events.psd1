@{
  Name = "fwmgr/get-events"
  Path = "/fwmgr/entities/events/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "firewall-management:read"
  Description = "List Firewall Management events"
  Parameters = @(
    @{
      Dynamic = "EventIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "(\w-){20}"
      Description = "The events to retrieve identified by ID"
      Position = 1
    }
  )
  Responses = @{
    400 = "fwmgr.msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "fwmgr.api.EventsResponse"
  }
}