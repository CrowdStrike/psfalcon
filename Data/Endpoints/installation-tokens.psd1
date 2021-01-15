@{
    "/installation-tokens/entities/audit-events/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "installation-tokens:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.auditEventDetailsResponseV1" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.auditEventDetailsResponseV1"
            }
        }
    }
    "/installation-tokens/entities/customer-settings/v1" = @{
        get = @{
            description = "List {0} settings"
            security = "installation-tokens:read"
            consumes = "application/json"
            produces = "application/json"
            responses = @{
                "api.customerSettingsResponseV1" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.customerSettingsResponseV1"
            }
        }
    }
    "/installation-tokens/entities/tokens/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "installation-tokens:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.tokenDetailsResponseV1" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.tokenDetailsResponseV1"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "installation-tokens:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.tokenCreateRequestV1"
            }
            responses = @{
                "api.tokenDetailsResponseV1" = @(201)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "installation-tokens:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,429,500)
                "msa.QueryResponse" = @(404)
                default = "msa.ReplyMetaOnly"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "installation-tokens:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
                schema = "api.tokenPatchRequestV1"
            }
            responses = @{
                "msa.QueryResponse" = @(200,404)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "msa.QueryResponse"
            }
        }
    }
    "/installation-tokens/queries/audit-events/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "installation-tokens:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 1000
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "msa.QueryResponse"
            }
        }
    }
    "/installation-tokens/queries/tokens/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "installation-tokens:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 1000
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "msa.QueryResponse"
            }
        }
    }
}