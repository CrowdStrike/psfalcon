@{
  Name = "samples/GetSampleV3"
  Method = "get"
  Path = "/samples/entities/samples/v3"
  Description = "Retrieves the file associated with the given ID (SHA256)"
  Headers = @{
    Accept = "application/octet-stream"
    ContentType = "*/*"
  }
  Permission = "samplestore:read"
  Parameters = @(
    @{
      Dynamic = "UserId"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
      Description = "User identifier"
    }
    @{
      Dynamic = "Sha256"
      Name = "ids"
      Type = "string"
      In = @( "query" )
      Pattern = "\w{64}"
      Required = $true
      Description = "Sha256 hash value of the file"
    }
    @{
      Dynamic = "PasswordProtected"
      Name = "password_protected"
      Type = "string"
      In = @( "query" )
      Description = "Flag whether the sample should be zipped and password protected with pass='infected'"
    }
  )
  Responses = @{
    400 = "msa.ReplyMetaOnly"
    404 = "msa.ReplyMetaOnly"
    500 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
