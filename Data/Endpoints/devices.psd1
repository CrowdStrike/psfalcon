@{
    "/devices/combined/host-group-members/v1" = @{
        get = @{
            description = "Search for detailed information about {0} members"
            security = "host-group:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "responses.HostGroupMembersV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.HostGroupMembersV1"
            }
        }
    }
    "/devices/combined/host-groups/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "host-group:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "group_type.asc","group_type.desc","modified_by.asc","modified_by.desc",
                        "modified_timestamp.asc","modified_timestamp.desc","name.asc","name.desc")
                }
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "responses.HostGroupsV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.HostGroupsV1"
            }
        }
    }
    "/devices/entities/devices-actions/v2" = @{
        post = @{
            description = "Perform actions on {0}s"
            security = "devices:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("contain","lift_containment","hide_host","unhide_host")
                }
                schema = "EntityAction"
            }
            responses = @{
                "msa.ReplyAffectedEntities" = @(202,400,409,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/devices/entities/devices/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "devices:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "domain.DeviceDetailsResponseSwagger" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.DeviceDetailsResponseSwagger"
            }
        }
    }
    "/devices/entities/host-group-actions/v1" = @{
        post = @{
            description = "Perform actions on {0}s"
            security = "host-group:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("add-hosts","remove-hosts")
                }
                ids = @{
                    dynamic = 'Id'
                    type = "string"
                    in = "body"
                    description = "Host group identifier"
                    position = 2
                }
                value = @{
                    dynamic = 'HostIds'
                    type = "array"
                    required = $true
                    parent = "action_parameters"
                    description = "One or more Host identifiers"
                    position = 3
                }
            }
            responses = @{
                "responses.HostGroupsV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.HostGroupsV1"
            }
        }
    }
    "/devices/entities/host-groups/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "host-group:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.HostGroupsV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.HostGroupsV1"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "host-group:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "requests.CreateGroupsV1"
            }
            responses = @{
                "responses.HostGroupsV1" = @(201,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "host-group:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "host-group:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "requests.UpdateGroupsV1"
            }
            responses = @{
                "responses.HostGroupsV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.HostGroupsV1"
            }
        }
    }
    "/devices/queries/devices-hidden/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "devices:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 5000
                }
                hidden_switch = @{
                    dynamic = "Hidden"
                    type = "switch"
                    required = $true
                    description = "Restrict search to hidden hosts"
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/devices/queries/devices-scroll/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "devices:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 5000
                }
                offset = @{
                    type = "string"
                    description = "Pagination token used to retrieve the next result set"
                }
            }
            responses = @{
                "domain.DeviceResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.DeviceResponse"
            }
        }
    }
    "/devices/queries/host-group-members/v1" = @{
        get = @{
            description = "Search for {0} members"
            security = "host-group:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/devices/queries/host-groups/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "host-group:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "group_type.asc","group_type.desc","modified_by.asc","modified_by.desc",
                        "modified_timestamp.asc","modified_timestamp.desc","name.asc","name.desc")
                }
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
}