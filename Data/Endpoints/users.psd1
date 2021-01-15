@{
    "/users/entities/users/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "usermgmt:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "domain.UserMetaDataResponse" = @(200)
                "msa.EntitiesResponse" = @(400,403,404)
                "msa.ReplyMetaOnly" = @(429)
                default = "domain.UserMetaDataResponse"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "usermgmt:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "domain.UserCreateRequest"
            }
            responses = @{
                "domain.UserMetaDataResponse" = @(201)
                "msa.EntitiesResponse" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        delete = @{
            description = "Remove a {0}"
            security = "usermgmt:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_uuid = @{
                    description = "{0} identifier"
                    dynamic = "Id"
                    in = "query"
                    required = $true
                    position = 1
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,404,429)
                default = "msa.ReplyMetaOnly"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "usermgmt:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_uuid = @{
                    description = "{0} identifier"
                    dynamic = "Id"
                    in = "query"
                    required = $true
                    position = 1
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
                schema = "domain.UpdateUserFields"
            }
            responses = @{
                "domain.UserMetaDataResponse" = @(200)
                "msa.EntitiesResponse" = @(400,403,404)
                "msa.ReplyMetaOnly" = @(429)
                default = "domain.UserMetaDataResponse"
            }
        }
    }
    "/users/queries/user-uuids-by-cid/v1" = @{
        get = @{
            description = "List all {0} identifiers"
            security = "usermgmt:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                uid = @{
                    description = "One or more {0}names"
                    dynamic = "Usernames"
                    type = "array"
                    in = "query"
                    position = 1
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/users/queries/user-uuids-by-email/v1" = @{
        get = @{
            description = "Retrieve a {0} identifier"
            security = "usermgmt:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                uid = @{
                    description = "One or more {0}names"
                    dynamic = "Usernames"
                    type = "array"
                    in = "query"
                    position = 1
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,403,404)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
}