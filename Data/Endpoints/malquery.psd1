@{
    "/malquery/aggregates/quotas/v1" = @{
        get = @{
            description = "Retrieve MalQuery quota information"
            security = "malquery:read"
            produces = "application/json"
            responses = @{
                "malquery.RateLimitsResponse" = @(200,404,500)
                "msa.ErrorsOnly" = @(400,401,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "malquery.RateLimitsResponse"
            }
        }
    }
    "/malquery/combined/fuzzy-search/v1" = @{
        post = @{
            description = "Perform a fuzzy MalQuery search"
            security = "malquery:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "malquery.FuzzySearchParametersV1"
                fuzzy_switch = @{
                    dynamic = "Fuzzy"
                    description = "Search MalQuery quickly but with more potential for false positives"
                    type = "switch"
                }
            }
            responses = @{
                "malquery.FuzzySearchResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(401,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "malquery.FuzzySearchResponse"
            }
        }
    }
    "/malquery/entities/download-files/v1" = @{
        get = @{
            description = "Download a {0}"
            security = "malquery:read"
            produces = "application/octet-stream"
            parameters = @{
                ids = @{
                    description = "Sha256 hash value"
                    dynamic = "Id"
                    type = "string"
                    in = "query"
                    pattern = $null
                    position = 1
                }
                outfile_path = @{
                    position = 2
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(400,429,500)
                "msa.ErrorsOnly" = @(401,403,404)
            }
        }
    }
    "/malquery/entities/metadata/v1" = @{
        get = @{
            description = "Retrieve metadata about a {0}"
            security = "malquery:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "malquery.SampleMetadataResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(401,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "malquery.SampleMetadataResponse"
            }
        }
    }
    "/malquery/entities/requests/v1" = @{
        get = @{
            description = "Retrieve detailed information about a MalQuery request"
            security = "malquery:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "malquery.RequestResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(401,403)
                "msa.ReplyMetaOnly" = @(429)
                default = "malquery.RequestResponse"
            }
        }
    }
    "/malquery/entities/samples-fetch/v1" = @{
        get = @{
            description = "Download a password-protected archive containing {0}s [password: 'infected']"
            security = "malquery:read"
            produces = "application/zip"
            parameters = @{
                ids = @{
                    dynamic = "Id"
                    description = "MalQuery sample archive download request identifier"
                    in = "query"
                    pattern = $null
                    required = $true
                }
                outfile_path = @{
                    position = 2
                }
            }
            responses = @{
                "msa.ErrorsOnly" = @(401,403)
                "msa.ReplyMetaOnly" = @(429)
                "malquery.ExternalQueryResponse" = @(500)
            }
        }
    }
    "/malquery/entities/samples-multidownload/v1" = @{
        post = @{
            description = "Schedule {0}s for download"
            security = "malquery:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "malquery.MultiDownloadRequestV1"
            }
            responses = @{
                "malquery.ExternalQueryResponse" = @(200,400,404,429,500)
                "msa.ErrorsOnly" = @(401,403)
                default = "malquery.ExternalQueryResponse"
            }
        }
    }
    "/malquery/queries/exact-search/v1" = @{
        post = @{
            description = "Perform an exact MalQuery search"
            security = "malquery:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "malquery.ExternalExactSearchParametersV1"
            }
            responses = @{
                "malquery.ExternalQueryResponse" = @(200,400,429,500)
                "msa.ErrorsOnly" = @(401,403)
                default = "malquery.ExternalQueryResponse"
            }
        }
    }
    "/malquery/queries/hunt/v1" = @{
        post = @{
            description = "Perform a MalQuery YARA Hunt"
            security = "malquery:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "malquery.ExternalHuntParametersV1"
            }
            responses = @{
                "malquery.ExternalQueryResponse" = @(200,400,429,500)
                "msa.ErrorsOnly" = @(401,403)
                default = "malquery.ExternalQueryResponse"
            }
        }
    }
}