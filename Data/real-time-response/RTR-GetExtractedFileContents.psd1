@{
  Name = "real-time-response/RTR-GetExtractedFileContents"
  Path = "/real-time-response/entities/extracted-file-contents/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/x-7z-compressed"
  }
  Permission = "real-time-response:write"
  Description = "Download a file extracted through a Real-time Response 'get' request"
  Parameters = @(
    @{
      Dynamic = "SessionId"
      Name = "session_id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Real-time Response session identifier"
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Position = 1
    }
    @{
      Dynamic = "Sha256"
      Name = "sha256"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{64}"
      Description = "Sha256 value of the extracted file"
      Position = 2
    }
    @{
      Dynamic = "Path"
      Type = "string"
      In = @( "outfile" )
      Required = $true
      Pattern = "\.7z$"
      Description = "Full destination path for .7z file"
      Position = 3
    }
  )
  Responses = @{
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    404 = "domain.APIError"
    429 = "msa.ReplyMetaOnly"
    500 = "domain.APIError"
    default = ""
  }
}