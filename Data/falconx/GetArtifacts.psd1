@{
  Name = "falconx/GetArtifacts"
  Path = "/falconx/entities/artifacts/v1"
  Method = "GET"
  Headers = @{
    Accept = "*/*"
    "Accept-Encoding" = "gzip"
  }
  Permission = "falconx-sandbox:read"
  Description = "Download IOC packs PCAP files and other analysis artifacts"
  Parameters = @(
    @{
      Dynamic = "ArtifactId"
      Name = "id"
      Type = "string"
      In = @( "query" )
      Required = $true
      Description = "Artifact identifier"
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
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}