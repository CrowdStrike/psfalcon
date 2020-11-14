@{
  Name = "processes/entities-processes"
  Path = "/processes/entities/processes/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "iocs:read"
  Description = "Retrieve detail about a process"
  Parameters = @(
    @{
      Dynamic = "ProcessIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "One or more process identifiers"
      Position = $null
    }
  )
  Responses = @{
    200 = "api.MsaProcessDetailResponse"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}