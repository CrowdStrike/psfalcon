@{
    "/cloud-connect-cspm-azure/entities/account/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "cspm-registration:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    required = $false
                }
                "scan-type" = @{}
                status = @{}
                limit = @{
                    max = 500
                }
                offset = @{}
            }
            responses = @{
                "registration.AzureAccountResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.AzureAccountResponseV1"
            }
        }
        post = @{
            description = "Provision {0}s"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "registration.AzureAccountCreateRequestExternalV1"
            }
            responses = @{
                "registration.AzureAccountResponseV1" = @(201,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "registration.BaseResponseV1" = @(200,207,400)
                "msa.ReplyMetaOnly" = @(403,429)
                "registration.AzureAccountResponseV1" = @(500)
                default = "registration.BaseResponseV1"
            }
        }
    }
    "/cloud-connect-cspm-azure/entities/client-id/v1" = @{
        patch = @{
            description = "Update an Azure service account and client identifier"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                id = @{
                    required = $true
                }
                "tenant-id" = @{}
            }
            responses = @{
                "registration.AzureServicePrincipalResponseV1" = @(201,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/cloud-connect-cspm-azure/entities/user-scripts-download/v1" = @{
        get = @{
            description = "Download a Bash script which grants access using Azure Cloud Shell"
            security = "cspm-registration:read"
            produces = "application/octet-stream"
            parameters = @{
                "tenant-id" = @{
                    position = 1
                }
                outfile_path = @{
                    pattern = "^*\.sh$"
                    position = 2
                }
            }
            responses = @{
                "registration.AzureProvisionGetUserScriptResponseV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.AzureProvisionGetUserScriptResponseV1"
            }
        }
    }
}