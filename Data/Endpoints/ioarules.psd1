@{
    "/ioarules/entities/pattern-severities/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.PatternsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.PatternsResponse"
            }
        }
    }
    "/ioarules/entities/platforms/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.PlatformsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.PlatformsResponse"
            }
        }
    }
    "/ioarules/entities/rule-groups/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.RuleGroupsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "api.RuleGroupsResponse"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "custom-ioa:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.RuleGroupCreateRequestV1"
            }
            responses = @{
                "api.RuleGroupsResponse" = @(201)
                "msa.ReplyMetaOnly" = @(403,404,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "custom-ioa:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
                comment = @{
                    position = 2
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,403,404,429)
                default = "msa.ReplyMetaOnly"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "custom-ioa:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.RuleGroupModifyRequestV1"
            }
            responses = @{
                "api.RuleGroupsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "api.RuleGroupsResponse"
            }
        }
    }
    "/ioarules/entities/rule-types/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.RuleTypesResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "api.RuleTypesResponse"
            }
        }
    }
    "/ioarules/entities/rules/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.RulesResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "api.RulesResponse"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "custom-ioa:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.RuleCreateV1"
            }
            responses = @{
                "api.RulesResponse" = @(201)
                "msa.ReplyMetaOnly" = @(403,404,429)
            }
        }
        delete = @{
            description = "Remove {0}s from a rule group"
            security = "custom-ioa:write"
            produces = "application/json"
            parameters = @{
                rule_group_id = @{
                    description = "Custom IOA Rule Group identifier"
                    in = "query"
                    required = $true
                    position = 1
                }
                ids = @{
                    position = 2
                }
                comment = @{
                    in = "query"
                    position = 3
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,403,404,429)
                default = "msa.ReplyMetaOnly"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "custom-ioa:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.RuleUpdatesRequestV1"
            }
            responses = @{
                "api.RulesResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "api.RulesResponse"
            }
        }
    }
    "/ioarules/entities/rules/validate/v1" = @{
        post = @{
            description = "Validate fields and patterns for a Custom IOA Rule"
            security = "custom-ioa:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                fields = @{
                    description = "An array of {0} properties"
                    type = "array"
                    in = "body"
                    required = $true
                    position = 1
                }
            }
            responses = @{
                "api.ValidationResponseV1" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "api.ValidationResponseV1"
            }
        }
    }
    "/ioarules/queries/pattern-severities/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                limit = @{
                    position = 1
                    max = 500
                }
                offset = @{
                    position = 2
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/ioarules/queries/platforms/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                limit = @{
                    position = 1
                    max = 500
                }
                offset = @{
                    position = 2
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/ioarules/queries/rule-groups-full/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                sort = @{
                    enum = @("created_by","created_on","description","enabled","modified_by","modified_on","name")
                }
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/ioarules/queries/rule-groups/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                sort = @{
                    enum = @("created_by","created_on","description","enabled","modified_by","modified_on","name")
                }
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/ioarules/queries/rule-types/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                limit = @{
                    max = 500
                    position = 1
                }
                offset = @{
                    position = 2
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/ioarules/queries/rules/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "custom-ioa:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                sort = @{
                    enum = @("rules.created_by","rules.created_on","rules.current_version.action_label",
                        "rules.current_version.description","rules.current_version.modified_by",
                        "rules.current_version.modified_on","rules.current_version.name",
                        "rules.current_version.pattern_severity","rules.enabled","rules.ruletype_name")
                }
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,404,429)
                default = "msa.QueryResponse"
            }
        }
    }
}