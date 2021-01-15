@{
    "/settings/entities/policy-details/v1" = @{
        get = @{
            description = "Retrieve detailed information about Falcon Horizon policies"
            security = "cspm-registration:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    pattern = "\d{*}"
                    in = "query"
                    required = $true
                }
            }
            responses = @{
                "registration.PolicyResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.PolicyResponseV1"
            }
        }
    }
    "/settings/entities/policy/v1" = @{
        get = @{
            description = "Search for Falcon Horizon policies"
            security = "cspm-registration:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                service = @{
                    description = "Cloud service type"
                    in = "query"
                    enum = @("EC2","IAM","KMS","ACM","ELB","NLB/ALB","EBS","RDS","S3","Redshift",
                        "NetworkSecurityGroup","VirtualNetwork","Disk","PostgreSQL","AppService","KeyVault",
                        "VirtualMachine","Monitor","StorageAccount","LoadBalancer","SQLServer")
                }
                "policy-id" = @{
                    description = "Policy identifier"
                    pattern = "\d{*}"
                    in = "query"
                }
            }
            responses = @{
                "registration.PolicySettingsResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.PolicySettingsResponseV1"
            }
        }
        patch = @{
            description = "Modify Falcon Horizon policies"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "registration.PolicyRequestExtV1"
            }
            responses = @{
                "registration.PolicySettingsResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.PolicySettingsResponseV1"
            }
        }
    }
    "/settings/scan-schedule/v1" = @{
        get = @{
            description = "Retrieve Falcon Horizon scan schedule settings"
            security = "cspm-registration:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                "cloud-platform" = @{
                    description = "Cloud platform"
                    type = "array"
                    in = "query"
                    enum = @("aws","azure","gcp")
                    position = 1
                }
            }
            responses = @{
                "registration.ScanScheduleResponseV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.ScanScheduleResponseV1"
            }
        }
        post = @{
            description = "Modify Falcon Horizon scan schedule settings"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "registration.ScanScheduleUpdateRequestV1"
            }
            responses = @{
                "registration.ScanScheduleResponseV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.ScanScheduleResponseV1"
            }
        }
    }
}