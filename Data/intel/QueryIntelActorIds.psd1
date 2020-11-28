@{
  Name = "intel/QueryIntelActorIds"
  Path = "/intel/queries/actors/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-actors:read"
  Description = "Get actor IDs that match provided FQL filters."
  Parameters = @(
    @{
      Dynamic = "Query"
      Name = "q"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Perform a generic substring search across all fields"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.ErrorsOnly"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
  }
}