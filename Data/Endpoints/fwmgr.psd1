@{
    "/fwmgr/entities/events/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "fwmgr.api.EventsResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.EventsResponse"
            }
        }
    }
    "/fwmgr/entities/firewall-fields/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "fwmgr.api.FirewallFieldsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.FirewallFieldsResponse"
            }
        }
    }
    "/fwmgr/entities/platforms/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "fwmgr.api.PlatformsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.PlatformsResponse"
            }
        }
    }
    "/fwmgr/entities/policies/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "fwmgr.api.PolicyContainersResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.PolicyContainersResponse"
            }
        }
        put = @{
            description = "Modify {0} settings"
            security = "firewall-management:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                policy_id = @{
                    description = "{0} identifier"
                    pattern = "\w{32}"
                    required = $true
                    position = 1
                }
                platform_id = @{
                    description = "Operating system platform identifier"
                    enum = @("0")
                    required = $true
                    position = 2
                }
                enforce = @{
                    description = "Enforce this policy on target Host Groups"
                    type = "boolean"
                    position = 3
                }
                rule_group_ids = @{
                    description = "One or more Firewall Rule Group identifiers"
                    type = "array"
                    position = 4
                }
                is_default_policy = @{
                    description = "Set as default policy"
                    type = "boolean"
                    position = 5
                }
                default_inbound = @{
                    description = "Default action for inbound traffic"
                    enum = @("ALLOW","DENY")
                    position = 6
                }
                default_outbound = @{
                    description = "Default action for outbound traffic"
                    enum = @("ALLOW","DENY")
                    position = 7
                }
                test_mode = @{
                    dynamic = "MonitorMode"
                    description = "Override all block rules in this policy and turn on monitoring"
                    type = "boolean"
                    position = 8
                }
                tracking = @{
                    position = 9
                }
            }
            responses = @{
                "fwmgr.msa.ReplyMetaOnly" = @(200,201,400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.msa.ReplyMetaOnly"
            }
        }
    }
    "/fwmgr/entities/rule-groups/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "fwmgr.api.RuleGroupsResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.RuleGroupsResponse"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "firewall-management:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                name = @{
                    required = $true
                    position = 1
                }
                enabled = @{
                    description = "{0} status"
                    required = $true
                    type = "boolean"
                    position = 2
                }
                clone_id = @{
                    position = 3
                }
                library = @{
                    description = "Clone default Falcon Firewall Rules"
                    in = "query"
                    type = "boolean"
                    position = 4
                }
                rules = @{
                    description = "An array of hashtables containing rule properties"
                    type = "array"
                    position = 5
                }
                description = @{
                    position = 6
                }
                comment = @{
                    position = 7
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(201)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "firewall-management:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
                comment = @{
                    position = 2
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.QueryResponse"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "firewall-management:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                id = @{
                    in = "body"
                    required = $true
                }
                diff_operations = @{
                    description = "An array of hashtables containing rule or rule group changes"
                    type = "array"
                    required = $true
                    position = 2
                }
                rule_ids = @{
                    description = "Rule identifiers"
                    type = "array"
                    required = $true
                    position = 3
                }
                rule_versions = @{
                    description = "Rule version values"
                    type = "array"
                    position = 4
                }
                tracking = @{
                    position = 5
                }
                comment = @{
                    position = 6
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.QueryResponse"
            }
        }
    }
    "/fwmgr/entities/rules/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "fwmgr.api.RulesResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.RulesResponse"
            }
        }
    }
    "/fwmgr/queries/events/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                offset = @{
                    type = "string"
                    description = "Pagination token used to retrieve the next result set"
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.QueryResponse"
            }
        }
    }
    "/fwmgr/queries/firewall-fields/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                platform_id = @{
                    description = "Operating system platform"
                    in = "query"
                    position = 1
                }
                limit = @{
                    position = 2
                }
                offset = @{
                    position = 3
                }
            }
            responses = @{
                "fwmgr.msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.msa.QueryResponse"
            }
        }
    }
    "/fwmgr/queries/platforms/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                limit = @{
                    position = 1
                }
                offset = @{
                    position = 2
                }
            }
            responses = @{
                "fwmgr.msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.msa.QueryResponse"
            }
        }
    }
    "/fwmgr/queries/policy-rules/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
                offset = @{
                    type = "string"
                    description = "Pagination token used to retrieve the next result set"
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.QueryResponse"
            }
        }
    }
    "/fwmgr/queries/rule-groups/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                offset = @{
                    type = "string"
                    description = "Pagination token used to retrieve the next result set"
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.QueryResponse"
            }
        }
    }
    "/fwmgr/queries/rules/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                offset = @{
                    type = "string"
                    description = "Pagination token used to retrieve the next result set"
                }
            }
            responses = @{
                "fwmgr.api.QueryResponse" = @(200)
                "fwmgr.msa.ReplyMetaOnly" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "fwmgr.api.QueryResponse"
            }
        }
    }
}