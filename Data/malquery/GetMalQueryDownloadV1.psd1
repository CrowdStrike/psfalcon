@{
  Name = "malquery/GetMalQueryDownloadV1"
  Path = "/malquery/entities/download-files/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/octet-stream"
  }
  Permission = "malquery:read"
  Description = "Download a file indexed by MalQuery using its SHA256 value"
  Parameters = @(
    @{
      Dynamic = "Sha256"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{64}"
      Description = "Sha256 value of the sample"
      Position = $null
    }
    @{
      Dynamic = "Path"
      Name = ""
      Type = "string"
      In = @(
        "outfile"
      )
      Required = $true
      Description = "Destination Path"
      Position = $null
    }
  )
  Responses = @{
    200 = ""
    400 = "msa.ReplyMetaOnly"
    401 = "msa.ErrorsOnly"
    403 = "msa.ErrorsOnly"
    404 = "msa.ErrorsOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}