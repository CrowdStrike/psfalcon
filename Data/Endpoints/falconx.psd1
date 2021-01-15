@{
    "/falconx/entities/artifacts/v1" = @{
        get = @{
            description = "Download artifacts from a {0}"
            security = "falconx-sandbox:read"
            produces = "application/octet-stream"
            parameters = @{
                id = @{
                    description = "Artifact identifier"
                    in = "query"
                    required = $true
                    position = 1
                }
                outfile_path = @{
                    position = 2
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(400,403,404,429,500)
            }
        }
    }
    "/falconx/entities/report-summaries/v1" = @{
        get = @{
            description = "Retrieve a summary level {0}"
            security = "falconx-sandbox:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
                summary_switch = @{
                    dynamic = "Summary"
                    description = "Restrict to summary level results"
                    type = "switch"
                    required = $true
                }
            }
            responses = @{
                "falconx.SummaryReportV1Response" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "falconx.SummaryReportV1Response"
            }
        }
    }
    "/falconx/entities/reports/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "falconx-sandbox:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "falconx.ReportV1Response" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "falconx.ReportV1Response"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "falconx-sandbox:write"
            produces = "application/json"
            parameters = @{
                ids = @{
                    description = "{0} identifier"
                    dynamic = "Id"
                    type = "string"
                    required = $true
                }
            }
            responses = @{
                "falconx.QueryResponse" = @(202)
                "falconx.ErrorsOnly" = @(400,403,404,500)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/falconx/entities/submissions/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "falconx-sandbox:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "falconx.SubmissionV1Response" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "falconx.SubmissionV1Response"
            }
        }
        post = @{
            description = "Submit a {0}"
            security = "falconx-sandbox:write"
            produces = "application/json"
            parameters = @{
                schema = "falconx.SubmissionParametersV1"
            }
            responses = @{
                "falconx.SubmissionV1Response" = @(200,400,429,500)
                "msa.ReplyMetaOnly" = @(403)
                default = "falconx.SubmissionV1Response"
            }
        }
    }
    "/falconx/queries/reports/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "falconx-sandbox:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/falconx/queries/submissions/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "falconx-sandbox:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
}