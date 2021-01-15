@{
    "/cloud-connect-cspm-aws/entities/account/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "cspm-registration:read"
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
                "organization-ids" = @{
                    position = 3
                }
                status = @{
                    position = 4
                }
                limit = @{
                    max = 500
                    position = 5
                }
                offset = @{
                    position = 6
                }
            }
            responses = @{
                "registration.AWSAccountResponseV2" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.AWSAccountResponseV2"
            }
        }
        post = @{
            description = "Provision {0}s"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "registration.AWSAccountCreateRequestExtV2"
            }
            responses = @{
                "registration.AWSAccountResponseV2" = @(201,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "cspm-registration:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    required = $false
                }
                "organization-ids" = @{}
            }
            responses = @{
                "registration.BaseResponseV1" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.BaseResponseV1"
            }
        }
    }
    "/cloud-connect-cspm-aws/entities/console-setup-urls/v1" = @{
        get = @{
            description = "Retrieve a URL that will grant access in AWS"
            security = "cspm-registration:read"
            consumes = "application/json"
            produces = "application/json"
            responses = @{
                "registration.AWSAccountConsoleURL" = @(200,207,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.AWSAccountConsoleURL"
            }
        }
    }
    "/cloud-connect-cspm-aws/entities/user-scripts-download/v1" = @{
        get = @{
            description = "Download a Bash script which grants access using AWS CLI"
            security = "cspm-registration:read"
            produces = "application/octet-stream"
            parameters = @{
                outfile_path = @{
                    pattern = "^*\.sh$"
                    position = 1
                }
            }
            responses = @{
                "registration.AWSProvisionGetAccountScriptResponseV2" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "registration.AWSProvisionGetAccountScriptResponseV2"
            }
        }
    }
}