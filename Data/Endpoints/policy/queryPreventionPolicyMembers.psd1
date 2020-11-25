@{
  Name = "policy/queryPreventionPolicyMembers"
  Path = "/policy/queries/prevention-members/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "prevention-policies:read"
  Description = "Search for members of a Prevention Policy in your environment by providing an FQL filter and paging details. Returns a set of Agent IDs which match the filter criteria"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "The ID of the Prevention Policy to search for members of"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.QueryResponse"
    400 = "msa.QueryResponse"
    403 = "msa.ErrorsOnly"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.QueryResponse"
  }
}