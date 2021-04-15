@{
    "/mssp/entities/children/v1" = @{
        get = @{
            description = "Retrieve {0} information"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "domain.ChildrenResponseV1"
                "msa.ReplyMetaOnly" = @(429)
                "msa.ErrorsOnly" = @(400,403)
            }
        }
    }
    "/mssp/entities/cid-group-members/v1" = @{
        get = @{
            description = "Retrieve {0} information"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_ids = @{
                    dynamic = "Ids"
                    description = "One or more CID Group identifiers"
                    type = "array"
                    in = "query"
                    position = 1
                    required = $true
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "domain.CIDGroupMembersResponseV1"
                "msa.ReplyMetaOnly" = @(429)
                "msa.ErrorsOnly" = @(400,403)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_id = @{
                    dynamic = "Id"
                    description = "CID Group identifier"
                    position = 1
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                cids = @{
                    dynamic = "CIDs"
                    description = "One or more CIDs"
                    type = "array"
                    position = 2
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "domain.CIDGroupMembersResponseV1"
                "msa.ReplyMetaOnly" = @(429)
                "msa.ErrorsOnly" = @(400,403)
            }
        }
        post = @{
            description = "Add {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_id = @{
                    dynamic = "Id"
                    description = "CID Group identifier"
                    position = 1
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                cids = @{
                    dynamic = "CIDs"
                    description = "One or more CIDs"
                    type = "array"
                    position = 2
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "domain.CIDGroupMembersResponseV1"
                "msa.ReplyMetaOnly" = @(429)
                "msa.ErrorsOnly" = @(400,403)
            }
        }
    }
    "/mssp/entities/cid-groups/v1" = @{
        delete = @{
            description = "Remove {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_ids = @{
                    dynamic = "Ids"
                    description = "One or more {0} identifiers"
                    type = "array"
                    in = "query"
                    position = 1
                    required = $true
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "msa.EntitiesResponse"
                "msa.ReplyMetaOnly" = @(429)
                "msa.ErrorsOnly" = @(400,403)
            }
        }
        get = @{
            description = "Retrieve detailed {0} information"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_ids = @{
                    dynamic = "Ids"
                    description = "One or more {0} identifiers"
                    type = "array"
                    in = "query"
                    position = 1
                    required = $true
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "domain.CIDGroupsResponseV1"
                "msa.ReplyMetaOnly" = @(429)
                "msa.ErrorsOnly" = @(400,403)
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_id = @{
                    dynamic = "Id"
                    description = "CID Group identifier"
                    position = 1
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                name = @{
                    description = "{0} name"
                    parent = "resources"
                    position = 3
                }
                description = @{
                    description = "{0} description"
                    parent = "resources"
                    position = 4
                }
            }
            responses = @{
                default = "domain.CIDGroupsResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        post = @{
            description = "Create {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                name = @{
                    description = "{0} name"
                    required = $true
                    parent = "resources"
                    position = 1
                }
                description = @{
                    description = "{0} description"
                    required = $true
                    parent = "resources"
                    position = 2
                }
            }
            responses = @{
                default = "domain.CIDGroupsResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/entities/mssp-roles/v1" = @{
        delete = @{
            description = "Remove roles from User Groups"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_id = @{
                    description = "CID Group Identifier"
                    position = 1
                    parent = "resources"
                    required = $true
                    pattern = "\w{32}"
                }
                user_group_id = @{
                    description = "User Group identifier"
                    position = 2
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                role_ids = @{
                    description = "One or more roles. Leave blank to remove User Group from CID Group."
                    type = "array"
                    parent = "resources"
                    position = 3
                }
            }
            responses = @{
                default = "domain.MSSPRoleResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        get = @{
            description = "Retrieve roles for User Groups"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    dynamic = "CombinedIds"
                    description = "One or more combined CID and User Group identifiers"
                    pattern = "\w{32}:\w{32}"
                }
            }
            responses = @{
                default = "domain.MSSPRoleResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        post = @{
            description = "Assign role(s) to CID and User Groups"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_id = @{
                    description = "CID Group Identifier"
                    position = 1
                    parent = "resources"
                    required = $true
                    pattern = "\w{32}"
                }
                user_group_id = @{
                    description = "User Group identifier"
                    position = 2
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                role_ids = @{
                    description = "One or more roles"
                    type = "array"
                    parent = "resources"
                    position = 3
                }
            }
            responses = @{
                default = "domain.MSSPRoleResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/entities/user-groups/v1" = @{
        delete = @{
            description = "Remove {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_group_ids = @{
                    dynamic = "Ids"
                    description = "One or more {0} identifiers"
                    type = "array"
                    in = "query"
                    position = 1
                    required = $true
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "msa.EntitiesResponse"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        get = @{
            description = "Retrieve detailed {0} information"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_group_ids = @{
                    dynamic = "Ids"
                    description = "One or more {0} identifiers"
                    type = "array"
                    in = "query"
                    position = 1
                    required = $true
                    pattern = "\w{32}"
                }
            }
            responses = @{
                default = "domain.UserGroupsResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_group_id = @{
                    dynamic = "Id"
                    description = "{0} identifier"
                    position = 1
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                name = @{
                    description = "{0} name"
                    required = $true
                    parent = "resources"
                    position = 2
                }
                description = @{
                    description = "{0} description"
                    required = $true
                    parent = "resources"
                    position = 3
                }
            }
            responses = @{
                default = "domain.UserGroupsResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        post = @{
            description = "Create {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                name = @{
                    description = "{0} name"
                    parent = "resources"
                    position = 2
                }
                description = @{
                    description = "{0} description"
                    parent = "resources"
                    position = 3
                }
            }
            responses = @{
                default = "domain.UserGroupsResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/entities/user-group-members/v1" = @{
        get = @{
            description = "Retrieve {0} information"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_group_ids = @{
                    dynamic = "Id"
                    in = "query"
                    required = $true
                    position = 1
                    description = "User Group identifier"
                }
            }
            responses = @{
                default = "domain.UserGroupMembersResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_group_id = @{
                    dynamic = "Id"
                    description = "User Group identifier"
                    position = 1
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                user_uuids = @{
                    dynamic = "UserIds"
                    description = "One or more User identifiers"
                    type = "array"
                    position = 2
                    required = $true
                    parent = "resources"
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                default = "domain.UserGroupMembersResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        post = @{
            description = "Add {0}s"
            security = "mssp:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_group_id = @{
                    dynamic = "Id"
                    description = "User Group identifier"
                    position = 1
                    required = $true
                    parent = "resources"
                    pattern = "\w{32}"
                }
                user_uuids = @{
                    dynamic = "UserIds"
                    description = "One or more User identifiers"
                    type = "array"
                    position = 2
                    required = $true
                    parent = "resources"
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                }
            }
            responses = @{
                default = "domain.UserGroupMembersResponseV1"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/queries/children/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                sort = @{
                    position = 1
                    enum = @("last_modified_timestamp")
                }
                limit = @{
                    position = 2
                }
                offset = @{
                    position = 3
                }
            }
            responses = @{
                default = "msa.QueryResponse"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/queries/cid-groups/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                name = @{
                    in = "query"
                    position = 1
                    description = "Name to lookup groups for"
                }
                sort = @{}
                limit = @{}
                offset = @{}
            }
            responses = @{
                default = "msa.QueryResponse"
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/queries/cid-group-members/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid = @{
                    dynamic = "Id"
                    in = "query"
                    position = 1
                    pattern = "\w{32}"
                    description = "CID Group identifier"
                }
                sort = @{}
                limit = @{}
                offset = @{}
            }
            responses = @{
                default = "msa.QueryResponse"
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/queries/user-groups/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                name = @{
                    in = "query"
                    position = 1
                    description = "Name to lookup groups for"
                }
                sort = @{}
                limit = @{}
                offset = @{}
            }
            responses = @{
                default = "msa.QueryResponse"
                "msa.ErrorsOnly" = @(400,403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/queries/user-group-members/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                user_uuid = @{
                    dynamic = "Id"
                    in = "query"
                    required = $true
                    position = 1
                    pattern = "(\w{32}|\w{8}-\w{4}-\w{4}-\w{4}-\w{12})"
                    description = "A User Group (to find members) or User identifier (to find assigned group)"
                }
                sort = @{}
                limit = @{}
                offset = @{}
            }
            responses = @{
                default = "msa.QueryResponse"
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/mssp/queries/mssp-roles/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "mssp:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                cid_group_id = @{
                    position = 1
                    in = "query"
                    description = "CID Group ID to fetch MSSP role for"
                }
                user_group_id = @{
                    position = 2
                    in = "query"
                    description = "User Group ID to fetch MSSP role for"
                }
                role_id = @{
                    in = "query"
                    description = "Role ID to fetch MSSP role for"
                    position = 3
                }
                sort = @{
                    position = 4
                }
                limit = @{
                    position = 5
                }
                offset = @{
                    position = 6
                }
            }
            responses = @{
                default = "msa.QueryResponse"
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
}