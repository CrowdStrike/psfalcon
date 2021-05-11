@{
    "/recon/entities/actions/v1" = @{
        post = @{
            description = "Create {0}s"
            security = "recon-monitoring-rules:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                rule_id = @{
                    description = "Falcon X Recon monitoring rule identifier"
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                    required = $true
                    position = 1
                }
                type = @{
                    in = "body"
                    description = "{0} type"
                    parent = "actions"
                    enum = @("email")
                    required = $true
                    position = 2
                }
                frequency = @{
                    description = "{0} frequency"
                    parent = "actions"
                    enum = @("asap","daily","weekly")
                    required = $true
                    position = 3
                }
                recipients = @{
                    description = "One or more email addresses"
                    type = "array"
                    parent = "actions"
                    required = $true
                    position = 4
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "msa.ErrorsOnly"= @(400,401,403,404,500)
                default = "domain.ActionEntitiesResponseV1"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "recon-monitoring-rules:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                id = @{
                    in = "body"
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                    required = $true
                    position = 1
                }
                frequency = @{
                    description = "{0} frequency"
                    enum = @("asap","daily","weekly")
                    position = 2
                }
                recipients = @{
                    description = "One or more email addresses"
                    type = "array"
                    position = 3
                }
                status = @{
                    description = "{0} status"
                    enum = @("enabled","muted")
                    position = 4
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.ActionEntitiesResponseV1"
            }
        }
        get = @{
            description = "Retrieve detailed {0} information"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.ActionEntitiesResponseV1"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "recon-monitoring-rules:write"
            produces = "application/json"
            parameters = @{
                id = @{
                    required = $true
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.QueryResponse"
            }
        }
    }
    "/recon/entities/notifications/v1" = @{
        patch = @{
            security = "recon-monitoring-rules:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                body = @{
                    schema = @{
                        id = @{
                            required = $true
                        }
                        assigned_to_uuid = @{
                            required = $true
                        }
                        status = @{
                            required = $true
                        }
                    }
                    required = $true
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.NotificationEntitiesResponseV1"
            }
        }
        get = @{
            description = "Retrieve detailed {0} information"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.NotificationEntitiesResponseV1"
            }
        }
        delete = @{
            security = "recon-monitoring-rules:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.NotificationIDResponse"
            }
        }
    }
    "/recon/entities/notifications-detailed/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information and include raw intelligence content"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
                intel_switch = @{
                    dynamic = "Intel"
                    type = "switch"
                    description = "Include raw intelligence content"
                    required = $true
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.NotificationDetailsResponseV1"
            }
        }
    }
    "/recon/entities/notifications-detailed-translated/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information, include raw intelligence content and translate to English"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
                combined_switch = @{
                    dynamic = "Combined"
                    type = "switch"
                    description = "Include raw intelligence content and translate to English"
                    required = $true
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.NotificationDetailsResponseV1"
            }
        }
    }
    "/recon/entities/notifications-translated/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information and translate to English"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
                translate_switch = @{
                    dynamic = "Translate"
                    type = "switch"
                    description = "Translate to English"
                    required = $true
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.NotificationEntitiesResponseV1"
            }
        }
    }
    "/recon/entities/rules/v1" = @{
        post = @{
            description = "Create {0}s"
            security = "recon-monitoring-rules:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                name = @{
                    required = $true
                    position = 1
                }
                topic = @{
                    required = $true
                    position = 2
                }
                filter = @{
                    in = "body"
                    required = $true
                    position = 3
                }
                priority = @{
                    required = $true
                    position = 4
                }
                permissions = @{
                    required = $true
                    position = 5
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.RulesEntitiesResponseV1"
            }
        }
        patch = @{
            description = "Modify {0}s"
            consumes = "application/json"
            produces = "application/json"
            security = "recon-monitoring-rules:write"
            parameters = @{
                id = @{
                    in = "body"
                    position = 1
                }
                name = @{
                    position = 2
                }
                filter = @{
                    in = "body"
                    position = 3
                }
                priority = @{
                    position = 4
                }
                permissions = @{
                    position = 5
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.RulesEntitiesResponseV1"
            }
            
        }
        get = @{
            description = "Retrieve detailed {0} information"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.RulesEntitiesResponseV1"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "recon-monitoring-rules:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.RuleQueryResponseV1"
            }
        }
    }
    "/recon/queries/actions/v1" = @{
        get = @{
            description = "Search for {0}s"
            produces = "application/json"
            security = "recon-monitoring-rules:read"
            parameters = @{
                filter = @{}
                q = @{}
                sort = @{
                    enum = @('created_timestamp|asc', 'created_timestamp|desc', 'updated_timestamp|asc',
                        'updated_timestamp|desc')
                    position = 3
                }
                limit = @{
                    max = 500
                    position = 4
                }
                offset = @{
                    position = 5
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.QueryResponse"
            }
        }
    }
    "/recon/queries/notifications/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                filter = @{}
                q = @{}
                sort = @{
                    enum = @('created_date|asc', 'created_date|desc', 'updated_date|asc',
                        'updated_date|desc')
                    position = 3
                }
                limit = @{
                    max = 500
                    position = 4
                }
                offset = @{
                    position = 5
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.QueryResponse"
            }
        }
    }
    "/recon/queries/rules/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "recon-monitoring-rules:read"
            produces = "application/json"
            parameters = @{
                filter = @{}
                q = @{}
                sort = @{
                    enum = @('created_timestamp|asc', 'created_timestamp|desc', 'last_updated_timestamp|asc',
                        'last_updated_timestamp|desc')
                    position = 3
                }
                limit = @{
                    max = 500
                    position = 4
                }
                offset = @{
                    position = 5
                }
            }
            responses = @{
                "msa.ReplyMetaOnly"= @(429)
                "domain.ErrorsOnly"= @(400,401,403,500)
                default = "domain.RuleQueryResponseV1"
            }
        }
    }
}