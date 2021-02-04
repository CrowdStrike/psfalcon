@{
    "/spotlight/entities/remediations/v2" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "spotlight-vulnerabilities:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                default = ""
            }
        }
    }
    "/spotlight/entities/vulnerabilities/v2" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "spotlight-vulnerabilities:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "domain.SPAPIVulnerabilitiesEntitiesResponseV2" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.SPAPIVulnerabilitiesEntitiesResponseV2"
            }
        }
    }
    "/spotlight/queries/vulnerabilities/v1" = @{
        get = @{
            description = "Search for {0} identifiers"
            security = "spotlight-vulnerabilities:read"
            produces = "application/json"
            parameters = @{
                filter = @{
                    required = $true
                }
                sort = @{}
                limit = @{
                    max = 400
                }
                after = @{
                    position = 4
                }
            }
            responses = @{
                "domain.SPAPIQueryVulnerabilitiesResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.SPAPIQueryVulnerabilitiesResponse"
            }
        }
    }
}