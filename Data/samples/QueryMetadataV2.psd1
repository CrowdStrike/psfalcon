@{
  Name = "samples/QueryMetadataV2"
  Path = "/samples/queries/metadata/v2"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
    ContentType = "*/*"
  }
  Permission = "samplestore:read"
  Description = "Find samples metadata based on a given filter currently allows only id/md5/sha1/pehash filtering."
  Parameters = @(
    @{
      Dynamic = "XCSUSERUUID"
      Name = "X-CS-USERUUID"
      Type = "string"
      In = @( "header" )
      Description = "User UUID"
    }
  )
}