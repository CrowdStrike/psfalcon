@{
  Name = "settings/GetCSPMPolicySettings"
  Description = "Returns information about current policy settings."
  Path = "/settings/entities/policy/v1"
  Method = "get"
  Headers = @{
    Accept = "application/json"
    ContentType = "application/json"
  }
  Permission = "cspm-registration:read"
  Parameters = @(
    @{
      Dynamic = "PolicyId"
      Name = "policy-id"
      Required = $false
      Description = "Policy identifier"
      Type = "string"
      In = @( "query" )
      Pattern = "\d{1,}"
      Position = 1
    }
    @{
      Dynamic = "Service"
      Name = "service"
      Required = $false
      Description = "Service type to filter policy settings by."
      Type = "string"
      In = @( "query" )
      Pattern = "^(EC2|IAM|KMS|ACM|ELB|NLB/ALB|EBS|RDS|S3|Redshift|NetworkSecurityGroup|VirtualNetwork|Disk|PostgreSQL|AppService|KeyVault|VirtualMachine|Monitor|StorageAccount|LoadBalancer|SQLServer)$"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "registration.PolicySettingsResponseV1"
  }
}