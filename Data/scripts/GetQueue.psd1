@{
  Name = "scripts/GetQueue"
  Description = "Create a report of with status of queued Real-time Response sessions"
  Permission = "real-time-response:read real-time-response:write real-time-response-admin:write"
  Parameters = @(
    @{
      Dynamic = "Days"
      Type = "int"
      Required = $false
      Description = "Number of days worth of results to retrieve [default: 7]"
      Position = 1
    }
  )
}