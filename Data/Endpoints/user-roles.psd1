@{
    "/user-roles/entities/user-roles/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "usermgmt:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "domain.UserRoleResponse" = @(200)
                "msa.EntitiesResponse" = @(400,403,404,500)
                "msa.ReplyMetaOnly" = @(429)
                default = "domain.UserRoleResponse"
            }
        }
        post = @{
            description = "Assign {0}s"
            security = "usermgmt:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "domain.RoleIDs"
                user_uuid = @{
                    dynamic = "UserId"
                    description = "Falcon User identifier"
                    in = "query"
                    required = $true
                    position = 2
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                "domain.UserRoleIDsResponse" = @(200)
                "msa.EntitiesResponse" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "domain.UserRoleIDsResponse"
            }
        }
        delete = @{
            description = "Revoke {0}s"
            security = "usermgmt:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
                user_uuid = @{
                    dynamic = "UserId"
                    description = "Falcon User identifier"
                    in = "query"
                    required = $true
                    position = 2
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                "domain.UserRoleIDsResponse" = @(200)
                "msa.EntitiesResponse" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "domain.UserRoleIDsResponse"
            }
        }
    }
    "/user-roles/queries/user-role-ids-by-cid/v1" = @{
        get = @{
            description = "List {0}s"
            security = "usermgmt:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_uuid = @{
                    dynamic = "UserId"
                    description = "List {0}s assigned to a User"
                    in = "query"
                    position = 1
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,403,404,500)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/user-roles/queries/user-role-ids-by-user-uuid/v1" = @{
        get = @{
            description = "List {0}s assigned to a User"
            security = "usermgmt:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_uuid = @{
                    dynamic = "UserId"
                    description = "Falcon User identifier"
                    in = "query"
                    required = $true
                    position = 1
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,403,500)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
}