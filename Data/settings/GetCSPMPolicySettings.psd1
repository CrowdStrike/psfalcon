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
      Dynamic = "Service"
      Name = "service"
      Required = $true
      Description = "Service type to filter policy settings by."
      Type = "string"
      In = @( "query" )
      Enum = @(
        "EC2"
        "IAM"
        "KMS"
        "ACM"
        "ELB"
        "NLB/ALB"
        "EBS"
        "RDS"
        "S3"
        "Redshift"
        "NetworkSecurityGroup"
        "VirtualNetwork"
        "Disk"
        "PostgreSQL"
        "AppService"
        "KeyVault"
        "VirtualMachine"
        "Monitor"
        "StorageAccount"
        "LoadBalancer"
        "SQLServer"
      )
      Position = 1
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    default = "registration.PolicySettingsResponseV1"
  }
}