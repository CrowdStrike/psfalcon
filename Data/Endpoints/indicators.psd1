@{
    "/indicators/aggregates/devices-count/v1" = @{
        get = @{
            description = "Retrieve the number of hosts that have observed a custom indicator"
            security = "iocs:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                type = @{}
                value = @{}
            }
            responses = @{
                "api.MsaReplyIOCDevicesCount" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyIOCDevicesCount"
            }
        }
    }
    "/indicators/entities/iocs/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "iocs:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.MsaReplyIOC" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyIOC"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "iocs:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.IOCViewRecord"
            }
            responses = @{
                "api.MsaReplyIOC" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyIOC"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "iocs:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    max = 200
                }
            }
            responses = @{
                "api.MsaReplyIOC" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyIOC"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "iocs:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    description = "{0} identifier"
                    required = $true
                    type = "array"
                    position = 1
                }
                schema = "api.IOCViewRecord"
            }
            responses = @{
                "api.MsaReplyIOC" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyIOC"
            }
        }
    }
    "/indicators/queries/devices/v1" = @{
        get = @{
            description = "Search for host identifiers that have observed a custom indicator"
            security = "iocs:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                type = @{}
                value = @{}
                limit = @{
                    position = 3
                }
                offset = @{
                    position = 4
                }
            }
            responses = @{
                "api.MsaReplyDevicesRanOn" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyDevicesRanOn"
            }
        }
    }
    "/indicators/queries/iocs/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "iocs:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                type = @{
                    type = "array"
                    required = $false
                }
                value = @{
                    type = "array"
                    required = $false
                }
                policies = @{
                    description = "Action to perform when the {0} is observed by a Host"
                    dynamic = "Policy"
                    in = "query"
                    type = "array"
                    enum = @("detect","none")
                    position = 3
                }
                sources = @{
                    description = "{0} source"
                    dynamic = "Source"
                    in = "query"
                    type = "array"
                    position = 4
                }
                share_levels = @{
                    description = "Filter by {0} visibility level"
                    dynamic = "ShareLevel"
                    in = "query"
                    enum = @("red")
                    position = 5
                }
                "from.expiration_timestamp" = @{
                    description = "Find {0}s created after this time (RFC-3339 timestamp)"
                    in = "query"
                    position = 6
                }
                "to.expiration_timestamp" = @{
                    description = "Find {0} created before this time (RFC-3339 timestamp)"
                    in = "query"
                    position = 7
                }
                created_by = @{
                    description = "User or API client that created the {0}"
                    in = "query"
                    position = 8
                }
                deleted_by = @{
                    description = "User or API client that deleted the {0}"
                    in = "query"
                    position = 9
                }
                include_deleted = @{
                    position = 10
                }
                limit = @{
                    position = 11
                }
                offset = @{
                    position = 12
                }
            }
            responses = @{
                "api.MsaReplyIOCIDs" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyIOCIDs"
            }
        }
    }
    "/indicators/queries/processes/v1" = @{
        get = @{
            description = "Search for process identifiers from Hosts that observed a custom indicator"
            security = "iocs:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                type = @{}
                value = @{}
                device_id = @{
                    description = "Host identifier"
                    dynamic = "HostId"
                    in = "query"
                    pattern = "\w{32}"
                    required = $true
                    position = 3
                }
                limit = @{
                    position = 4
                }
                offset = @{
                    position = 5
                }
                detailed_switch = @{
                    dynamic = "Detailed"
                    type = "switch"
                    description = "Retrieve detailed information"
                }
            }
            responses = @{
                "api.MsaReplyProcessesRanOn" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaReplyProcessesRanOn"
            }
        }
    }
}