@{
  Name = "cloud-connect-cspm-aws/DeleteCSPMAwsAccount"
  Method = "delete"
  Path = "/cloud-connect-cspm-aws/entities/account/v1"
  Description = "Deletes an existing AWS account or organization in our system."
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:write"
  Parameters = @(
    @{
      Dynamic = "AccountIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Description = "AWS account IDs to remove"
    }
    @{
      Dynamic = "OrganizationIds"
      Name = "organization-ids"
      Type = "array"
      In = @( "query" )
      Pattern = "^o-[0-9a-z]{10,32}$"
      Description = "AWS organization IDs to remove"
    }
  )
  Responses = @{
    default = "registration.BaseResponseV1"
    429 = "msa.ReplyMetaOnly"
    403 = "msa.ReplyMetaOnly"
  }
}
