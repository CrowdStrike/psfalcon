@{
    "/detects/entities/detects/v2" = @{
        patch = @{
            description = "Modify the state, assignee, and visibility of {0}s"
            security = "detects:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "domain.DetectsEntitiesPatchRequest"
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,429,500)
                default = "msa.ReplyMetaOnly"
            }
        }
    }
    "/detects/entities/summaries/GET/v1" = @{
        post = @{
            description = "Retrieve detailed {0} information"
            security = "detects:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    in = "body"
                    max = 1000
                }
            }
            responses = @{
                "domain.MsaDetectSummariesResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.MsaDetectSummariesResponse"
            }
        }
    }
    "/detects/queries/detects/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "detects:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                limit = @{
                    max = 5000
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