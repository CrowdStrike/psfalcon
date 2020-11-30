@{
  Name = "scanner/ScanSamples"
  Description = "Submit a volume of files for ml scanning. Time required for analysis increases with the number of samples in a volume but usually it should take less than 1 minute"
  Path = "/scanner/entities/scans/v1"
  Method = "post"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "quick-scan:write"
  Parameters = @{
    Dynamic = "Sha256s"
    Name = "samples"
    Required = $true
    Type = "array"
    In = @( "body" )
    Pattern = "\w{64}"
    Description = "One or more SHA256 hash values to submit as a volume scan"
    Position = 1
  }
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "mlscanner.QueryResponse"
  }
}