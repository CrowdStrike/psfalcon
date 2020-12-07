@{
  Name = "settings/UpdateCSPMScanSchedule"
  Method = "post"
  Path = "/settings/scan-schedule/v1"
  Description = "Updates scan schedule configuration for one or more cloud platforms."
  Headers = @{
    ContentType = "application/json"
    Accept = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{ 
      Dynamic = "CloudPlatform"
      Name = "cloud_platform"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Required = $true
      Position = $null
      Description = $null
    } 
    @{ 
      Dynamic = "NextScan"
      Name = "next_scan_timestamp"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Required = $true
      Position = $null
      Description = $null
    } 
    @{ 
      Dynamic = "ScanSchedule"
      Name = "scan_schedule"
      Type = "string"
      Parent = "resources"
      In = @( "body" )
      Enum = @(
        "2h"
        "6h"
        "12h"
        "24h"
      )
      Required = $true
      Position = $null
      Description = $null
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    default = "registration.ScanScheduleResponseV1"
    429 = "msa.ReplyMetaOnly"
  }
}
