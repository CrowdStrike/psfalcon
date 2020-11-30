@{
  Name = "intel/GetIntelIndicatorEntities"
  Path = "/intel/entities/indicators/GET/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "falconx-indicators:read"
  Description = "List detailed information about Indicators"
  Parameters = @(
    @{
      Dynamic = "IndicatorIds"
      Name = "ids"
      Type = "array"
      In = @( "body" )
      Required = $true
      Description = "One or more indicator identifiers"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
    default = "domain.PublicIndicatorsV3Response"
  }
}