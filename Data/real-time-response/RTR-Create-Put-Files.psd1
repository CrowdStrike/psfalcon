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
      Position = $null
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Description = "A description of the file"
      Position = $null
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Description = "Optional name to use for the script"
      Position = $null
    }
    @{
      Dynamic = "Comment"
      Name = "comments_for_audit_log"
      Type = "string"
      In = @( "formdata" )
      Required = $false
      Max = 4096
      Description = "A comment for the audit log"
      Position = $null
    }
  )
  Responses = @{
    200 = "msa.ReplyMetaOnly"
    400 = "domain.APIError"
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
  }
}