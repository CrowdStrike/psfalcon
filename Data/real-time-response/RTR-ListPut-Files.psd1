@{
  Name = "real-time-response/RTR-ListPut-Files"
  Path = "/real-time-response/queries/put-files/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Get a list of put-file ID's that are available to the user for the `put` command."
  Parameters = @()
  Responses = @{
    200 = "binservclient.MsaPutFileResponse"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
  }
}