@{
  Name = "samples/UploadSampleV3"
  Method = "post"
  Path = "/samples/entities/samples/v3"
  Description = "Upload a file for further cloud analysis. After uploading, call the specific analysis API endpoint."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/octet-stream"
  }
  Permission = "samplestore:write"
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
      Dynamic = "Path"
      Name = "body"
      Type = "string"
      In = @( "body" )
      Pattern = "\.(acm|apk|ax|axf|bin|chm|cpl|dll|doc|docx|drv|efi|elf|eml|exe|hta|jar|js|ko|lnk|o|ocx|mod|msg|mui|pdf|pl|ppt|pps|pptx|ppsx|prx|ps1|psd1|psm1|pub|puff|py|rtf|scr|sct|so|svg|svr|swf|sys|tsp|vbe|vbs|wsf|xls|xlsx)+$"
      Script = '[System.IO.Path]::IsPathRooted($_)'
      ScriptError = "Relative paths are not permitted."
      Required = $true
      Description = "Path to the file"
      Position = $null
    }
    @{
      Dynamic = "Filename"
      Name = "file_name"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "Filename"
      Position = $null
    }
    @{
      Dynamic = "Comment"
      Name = "comment"
      Type = "string"
      In = @( "query" )
      Required = $false
      Description = "A comment to identify for other users to identify this sample"
      Position = $null
    }
    @{
      Dynamic = "IsConfidential"
      Name = "is_confidential"
      Type = "bool"
      In = @( "query" )
      Required = $false
      Description = "Visibility of the sample in Falcon MalQuery"
      Position = $null
    }
    @{
      Dynamic = "Upfile"
      Name = "upfile"
      Type = "file"
      In = @( "formData" )
      Required = $false
      Position = $null
      Description = "The binary file."
    }
  )
  Responses = @{
    default = "samplestore.SampleMetadataResponseV2"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
