@{
  Name = "real-time-response/RTR-ListScripts"
  Path = "/real-time-response/queries/scripts/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "real-time-response-admin:write"
  Description = "Get a list of custom-script ID's that are available to the user for the `runscript` command."
  Parameters = @()
  Responses = @{
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
    default = "binservclient.MsaPutFileResponse"
  }
}