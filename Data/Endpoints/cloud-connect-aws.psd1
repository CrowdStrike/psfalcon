@{
    "/cloud-connect-aws/combined/accounts/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "cloud-connect-aws:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "models.AWSAccountsV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "models.AWSAccountsV1"
            }
        }
    }
    "/cloud-connect-aws/combined/settings/v1" = @{
        get = @{
            description = "List global settings applied to all provisioned {0}s"
            security = "cloud-connect-aws:read"
            produces = "application/json"
            responses = @{
                "models.CustomerConfigurationsV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "models.CustomerConfigurationsV1"
            }
        }
    }
    "/cloud-connect-aws/entities/accounts/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "cloud-connect-aws:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    max = 5000
                }
            }
            responses = @{
                "models.AWSAccountsV1" = @(200,400,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "models.AWSAccountsV1"
            }
        }
        post = @{
            description = "Provision {0}s"
            security = "cloud-connect-aws:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                mode = @{}
                schema = "AwsAccount"
            }
            responses = @{
                "models.AWSAccountsV1" = @(201,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "cloud-connect-aws:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "models.BaseResponseV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "models.BaseResponseV1"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "cloud-connect-aws:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "AwsAccount"
            }
            responses = @{
                "models.AWSAccountsV1" = @(200,400,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "models.AWSAccountsV1"
            }
        }
    }
    "/cloud-connect-aws/entities/settings/v1" = @{
        post = @{
            description = "Add or modify global settings for {0}s"
            security = "cloud-connect-aws:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "models.ModifyAWSCustomerSettingsV1"
            }
            responses = @{
                "models.CustomerConfigurationsV1" = @(201,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/cloud-connect-aws/entities/verify-account-access/v1" = @{
        post = @{
            description = "Perform an access verification check on {0}s"
            security = "cloud-connect-aws:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "models.VerifyAccessResponseV1" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "models.VerifyAccessResponseV1"
            }
        }
    }
    "/cloud-connect-aws/queries/accounts/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "cloud-connect-aws:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
}