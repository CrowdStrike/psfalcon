@{
    "/cloud-connect-azure/entities/account/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "d4c-registration:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
                "scan-type" = @{}
            }
            responses = @{
                "registration.AzureAccountResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.AzureAccountResponseV1"
            }
        }
        post = @{
            description = "Provision {0}s"
            security = "d4c-registration:write"
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
    }
    "/cloud-connect-azure/entities/client-id/v1" = @{
        patch = @{
            description = "Update an Azure service account and client identifier"
            security = "d4c-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                id = @{
                    required = $true
                }
            }
            responses = @{
                "registration.AzureServicePrincipalResponseV1" = @(201,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/cloud-connect-azure/entities/user-scripts-download/v1" = @{
        get = @{
            description = "Download a Bash script which grants access using Azure Cloud Shell"
            security = "d4c-registration:read"
            produces = "application/octet-stream"
            parameters = @{
                outfile_path = @{
                    pattern = "^*\.sh$"
                    position = 1
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