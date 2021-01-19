@{
    "/sensors/combined/installers/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "sensor-installers:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "domain.SensorInstallersV1" = @(200)
                "msa.QueryResponse" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.SensorInstallersV1"
            }
        }
    }
    "/sensors/entities/datafeed-actions/v1/partition" = @{
        post = @{
            description = "Refresh an active event stream"
            security = "streaming:read"
            produces = "application/json"
            parameters = @{
                appId = @{
                    position = 1
                    required = $true
                }
                partition = @{
                    description = "Partition number to refresh"
                    type = "integer"
                    in = "path"
                    required = $true
                    position = 2
                }
            }
            responses = @{
                default = "msa.ReplyMetaOnly"
            }
        }
    }
    "/sensors/entities/datafeed/v2" = @{
        get = @{
            description = "List {0}s"
            security = "streaming:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                appId = @{
                    position = 1
                }
                format = @{
                    description = "Format for streaming events [default: json]"
                    enum = @("json","flatjson")
                    in = "query"
                    position = 2
                }
            }
            responses = @{
                "main.discoveryResponseV2" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "main.discoveryResponseV2"
            }
        }
    }
    "/sensors/entities/download-installer/v1" = @{
        get = @{
            description = "Download {0}s"
            security = "sensor-installers:read"
            consumes = "application/json"
            produces = "application/octet-stream"
            parameters = @{
                id = @{
                    in = "query"
                    required = $true
                }
                outfile_path = @{
                    position = 2
                }
            }
            responses = @{
                "domain.DownloadItem" = @(200)
                "msa.QueryResponse" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.DownloadItem"
            }
        }
    }
    "/sensors/entities/installers/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "sensor-installers:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "domain.SensorInstallersV1" = @(200,207)
                "msa.QueryResponse" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.SensorInstallersV1"
            }
        }
    }
    "/sensors/queries/installers/ccid/v1" = @{
        get = @{
            description = "Retrieve your customer checksum identifier (CCID)"
            security = "sensor-installers:read"
            consumes = "application/json"
            produces = "application/json"
            responses = @{
                "msa.QueryResponse" = @(200,400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/sensors/queries/installers/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "sensor-installers:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
}