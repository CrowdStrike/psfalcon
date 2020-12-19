@{
  Name = "real-time-response/RTR-UpdateScripts"
  Path = "/real-time-response/entities/scripts/v1"
  Method = "PATCH"
  Headers = @{
    Accept = "application/json"
    ContentType = "multipart/form-data"
  }
  Permission = "real-time-response-admin:write"
  Description = "Upload a new script to replace an existing one"
  Parameters = @(
    @{
      Dynamic = "ScriptId"
      Name = "id"
      Type = "string"
      In = @( "formdata" )
      Required = $true
      Description = "The identifier of the script to update"
    }
    @{
      Dynamic = "Path"
      Name = "file"
      Type = "string"
      In = @( "formdata" )
      Description = "Script to upload"
    }
    @{
      Dynamic = "Platform"
      Name = "platform"
      Type = "array"
      In = @( "formdata" )
      Description = "Operating system platform [default: windows]"
    }
    @{
      Dynamic = "Description"
      Name = "description"
      Type = "string"
      In = @( "formdata" )
      Description = "A description of the script"
    }
    @{
      Dynamic = "Name"
      Name = "name"
      Type = "string"
      In = @( "formdata" )
      Description = "Optional name to use for the script"
    }
    @{
      Dynamic = "Comment"
      Name = "comments_for_audit_log"
      Type = "string"
      In = @( "formdata" )
      Max = 4096
      Description = "A comment for the audit log"
    }
    @{
      Dynamic = "PermissionType"
      Name = "permission_type"
      Type = "string"
      In = @( "formdata" )
      Description = "Permission level [private: uploader only group: admins public: admins and active responders]"
    }
  )
  Responses = @{
    400 = "domain.APIError"
    default = "msa.ReplyMetaOnly"
  }
}