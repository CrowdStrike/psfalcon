@{
  Name = "samples/GetSampleV2"
  Path = "/samples/entities/samples/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/octet-stream"
  }
  Permission = "falconx-sandbox:read"
  Description = "Retrieves the file associated with the given ID (SHA256)"
  Parameters = @(
    @{
      Dynamic = "UserUuid"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Required = $false
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
      Position = $null
    }
    @{
      Dynamic = "Sha256"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Pattern = "\w{64}"
      Required = $true
      Description = "Sha256 hash value of the file"
      Position = $null
    }
    @{
      Dynamic = "PasswordProtected"
      Name = "password_protected"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Flag whether the sample should be zipped and password protected with pass='infected'"
      Position = $null
    }
  )
  Responses = @{
    200 = ""
    400 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
  }
}