@{
    "/scanner/entities/scans/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "quick-scan:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "mlscanner.ScanV1Response" = @(200,400,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "mlscanner.ScanV1Response"
            }
        }
        post = @{
            description = "Submit a {0}"
            security = "quick-scan:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "mlscanner.SamplesScanParameters"
            }
            responses = @{
                "mlscanner.QueryResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "mlscanner.QueryResponse"
            }
        }
    }
    "/scanner/queries/scans/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "quick-scan:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 500
                }
            }
            responses = @{
                "mlscanner.QueryResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "mlscanner.QueryResponse"
            }
        }
    }
}