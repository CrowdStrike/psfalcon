@{
    "/falcon-complete-dashboards/queries/allowlist/v1" = @{
        get = @{
          description = "Search for {0} allowlist tickets"
            security = "falconcomplete-dashboard:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/falcon-complete-dashboards/queries/incidents/v1" = @{
        get = @{
            description = "Search for {0} incident identifiers"
            security = "falconcomplete-dashboard:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/falcon-complete-dashboards/queries/remediations/v1" = @{
        get = @{
            description = "Search for {0} remediation tickets"
            security = "falconcomplete-dashboard:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/falcon-complete-dashboards/queries/detects/v1" = @{
        get = @{
            description = "Search for {0} detection identifiers"
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
            security = "falconcomplete-dashboard:read"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            produces = "application/json"
            consumes = "application/json"
        }
    }
    "/falcon-complete-dashboards/queries/devicecount-collections/v1" = @{
        get = @{
            description = "Search for {0} device count collection identifiers"
            security = "falconcomplete-dashboard:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/falcon-complete-dashboards/queries/escalations/v1" = @{
        get = @{
            description = "Search for {0} escalation tickets"
            security = "falconcomplete-dashboard:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/falcon-complete-dashboards/queries/blocklist/v1" = @{
        get = @{
            description = "Search for {0} blocklist tickets"
            security = "falconcomplete-dashboard:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
}