@{
  Name = "malquery/GetMalQueryRequestV1"
  Path = "/malquery/entities/requests/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "malquery:read"
  Description = "Check the status and results of a MalQuery request"
  Parameters = @(
    @{
      Dynamic = "QueryIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Required = $true
      Description = "MalQuery request identifier"
      Position = $null
    }
  )
  Responses = @{
    200 = "malquery.RequestResponse"
    400 = "malquery.RequestResponse"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "malquery.RequestResponse"
  }
}