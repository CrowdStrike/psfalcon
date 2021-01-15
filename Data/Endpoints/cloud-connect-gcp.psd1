@{
    "/cloud-connect-gcp/entities/account/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "d4c-registration:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                "scan-type" = @{
                    position = 1
                }
                ids = @{
                    required = $false
                    position = 2
                }
            }
            responses = @{
                "registration.GCPAccountResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.GCPAccountResponseV1"
            }
        }
        post = @{
            description = "Provision {0}s"
            security = "d4c-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "registration.GCPAccountCreateRequestExtV1"
            }
            responses = @{
                "registration.GCPAccountResponseV1" = @(201,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/cloud-connect-gcp/entities/user-scripts-download/v1" = @{
        get = @{
            description = "Download a Bash script which grants access using GCP CLI"
            security = "d4c-registration:read"
            produces = "application/octet-stream"
            parameters = @{
                outfile_path = @{
                    pattern = "^*\.sh$"
                    position = 1
                }
            }
            responses = @{
                "registration.GCPProvisionGetUserScriptResponseV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.GCPProvisionGetUserScriptResponseV1"
            }
        }
    }
}