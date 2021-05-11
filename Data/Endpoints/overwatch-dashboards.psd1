@{
    "/overwatch-dashboards/aggregates/incidents-global-counts/v1" = @{
        get = @{
            description = "Get the total number of {0} incidents across all customers"
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.FacetsResponse"
            }
            security = "overwatch-dashboard:read"
            parameters = @{
                filter = @{
                    required = $true
                }
            }
            produces = "application/json"
            consumes = "application/json"
        }
    }
    "/overwatch-dashboards/aggregates/detections-global-counts/v1" = @{
        get = @{
            description = "Get the total number of {0} detections across all customers"
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.FacetsResponse"
            }
            security = "overwatch-dashboard:read"
            parameters = @{
                filter = @{
                    required = $true
                }
            }
            produces = "application/json"
            consumes = "application/json"
        }
    }
    "/overwatch-dashboards/aggregates/ow-events-global-counts/v1" = @{
        get = @{
            description = "Get the total number of {0} events across all customers"
            responses = @{
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.FacetsResponse"
            }
            security = "overwatch-dashboard:read"
            parameters = @{
                filter = @{
                    required = $true
                }
            }
            produces = "application/json"
            consumes = "application/json"
        }
    }
}