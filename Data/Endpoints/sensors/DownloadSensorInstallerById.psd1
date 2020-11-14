@{
  Name = "sensors/DownloadSensorInstallerById"
  Path = "/sensors/entities/download-installer/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "sensor-installers:read"
  Description = "Download a sensor installer"
  Parameters = @(
    @{
      Dynamic = "InstallerId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Pattern = "\w{64}"
      Description = "SHA256 hash value of the installer to download"
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
      Pattern = "\.(deb|exe|html|pkg|rpm)+$"
      Description = "Destination path"
      Position = $null
    }
  )
  Responses = @{
    200 = "domain.DownloadItem"
    400 = "msa.QueryResponse"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.QueryResponse"
    429 = "msa.ReplyMetaOnly"
  }
}