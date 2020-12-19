@{
  Name = "settings/GetCSPMScanSchedule"
  Method = "get"
  Path = "/settings/scan-schedule/v1"
  Description = "Returns scan schedule configuration for one or more cloud platforms."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:read"
  Parameters = @(
    @{
      Dynamic = "Platform"
      Name = "cloud-platform"
      Type = "array"
      In = @( "query" )
      Enum = @(
        "aws",
        "azure",
        "gcp"
      )
      Position = 1
      Description = "Cloud Platform"
    }
  )
  Responses = @{
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    default = "registration.ScanScheduleResponseV1"
  }
}
