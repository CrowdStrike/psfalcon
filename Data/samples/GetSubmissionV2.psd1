@{
  Name = "samples/GetSubmissionV2"
  Path = "/samples/entities/submissions/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "samplestore:read"
  Description = "Gets the submissions entities."
  Parameters = @(
    @{
      Dynamic = "UserId"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
      Position = $null
    }
    @{
      Dynamic = "SubmissionIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "A list of submission IDs"
      Position = $null
    }
  )
}