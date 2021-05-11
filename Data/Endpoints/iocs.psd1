@{
    "/iocs/combined/indicators/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "ioc:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                filter = @{}
                sort = @{
                    enum = @("action","applied_globally","metadata.av_hits","metadata.company_name.raw",
                        "created_by","created_on","expiration","expired","metadata.filename.raw","modified_by",
                        "modified_on","metadata.original_filename.raw","metadata.product_name.raw",
                        "metadata.product_version","severity_number","source","type","value")
                }
                limit = @{}
                offset = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.IndicatorQueryResponse"
            }
        }
    }
    "/iocs/entities/indicators/v1" = @{
        delete = @{
            description = "Remove {0}s. 'Filter' takes precedence over 'Ids'."
            security = "ioc:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{
                    position = 1
                    required = $false
                }
                filter = @{
                    description = "Falcon Query Language expression to find and delete {0}s"
                    position = 2
                }
                comment = @{
                    position = 3
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.IndicatorQueryResponse"
            }
        }
        get = @{
            description = "Retrieve detailed {0} information"
            security = "ioc:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.IndicatorRespV1"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "ioc:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.IndicatorUpdateReqV1"
                comment = @{
                    in = "body"
                    position = 12
                }
                retrodetects = @{
                    dynamic = "RetroDetects"
                    in = "query"
                    type = "boolean"
                    description = "Generate retroactive detections for hosts that have observed the {0}s"
                    position = 13
                }
                ignore_warnings = @{
                    in = "query"
                    type = "boolean"
                    description = "Ignore warnings and modify all {0}s"
                    position = 14
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.IndicatorRespV1"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "ioc:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "api.IndicatorCreateReqV1"
                comment = @{
                    in = "body"
                    position = 13
                }
                retrodetects = @{
                    dynamic = "RetroDetects"
                    in = "query"
                    type = "boolean"
                    description = "Generate retroactive detections for hosts that have observed the {0}"
                    position = 14
                }
                ignore_warnings = @{
                    in = "query"
                    type = "boolean"
                    description = "Ignore warnings and create all {0}s"
                    position = 15
                }
            }
            responses = @{
                "api.IndicatorRespV1" = @(201)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/iocs/queries/indicators/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "ioc:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                filter = @{}
                sort = @{
                    enum = @("action","applied_globally","metadata.av_hits","metadata.company_name.raw",
                        "created_by","created_on","expiration","expired","metadata.filename.raw","modified_by",
                        "modified_on","metadata.original_filename.raw","metadata.product_name.raw",
                        "metadata.product_version","severity_number","source","type","value")
                }
                limit = @{
                    max = 2000
                }
                offset = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.IndicatorQueryResponse"
            }
        }
    }
}