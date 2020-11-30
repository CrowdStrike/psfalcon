@{
  Name = "real-time-response/RTR-CreatePut-Files"
  Path = "/real-time-response/entities/put-files/v1"
  Method = "POST"
  Headers = @{
    Accept = "application/json"
    ContentType = "multipart/form-data"
  }
  Permission = "real-time-response-admin:write"
  Description = "Upload a new put-file to use for the RTR 'put' command."
  Parameters = @(
    @{
      Dynamic = "Path"
      Name = "file"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Script = '[System.IO.Path]::IsPathRooted($_)'
      ScriptError = "Relative paths are not permitted."
      Description = "File to upload"
      Position = 1
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Description = "A description of the file"
      Position = 3
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Description = "Optional name to use for the script"
      Position = 2
    }
    @{
      Dynamic = "Comment"
      Name = "comments_for_audit_log"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Max = 4096
      Description = "A comment for the audit log"
      Position = 4
    }
  )
  Responses = @{
    400 = "domain.APIError"
    default = "msa.ReplyMetaOnly"
  }
}