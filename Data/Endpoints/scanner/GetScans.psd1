@{
  Name = "scanner/GetScans"
  Description = "Check the status of a volume scan. Time required for analysis increases with the number of samples in a volume but usually it should take less than 1 minute"
  Path = "/scanner/entities/scans/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "quick-scan:read"
  Parameters = @{
    Dynamic = "ScanIds"
    Name = "ids"
    Type = "array"
    In = @(
      "query"
    )
    Required = $true
    Pattern = "\w{32}_\w{32}"
    Description = "One or more volume scan identifiers"
    Position = $null
  }
  Responses = @{
    200 = "mlscanner.ScanV1Response"
    400 = "mlscanner.ScanV1Response"
    403 = "msa.ReplyMetaOnly"
    404 = "mlscanner.ScanV1Response"
    429 = "msa.ReplyMetaOnly"
    500 = "mlscanner.ScanV1Response"
  }
}