@{
  Name = "ioarules/validate"
  Description = "Validates field values and checks for matches if a test string is provided."
  Path = "/ioarules/entities/rules/validate/v1"
  Method = "post"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "custom-ioa:write"
  Parameters = @(
    @{
      Dynamic = "Fields"
      Name = "fields"
      Required = $true
      Type = "array"
      In = @( "body" )
      Description = "An array of hashtables containing rule properties"
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "api.ValidationResponseV1"
  }
}