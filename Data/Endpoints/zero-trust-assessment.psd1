@{
    "/zero-trust-assessment/entities/assessments/v1" = @{
        get = @{
            description = "Retrieve a Zero Trust Assessment result for one or more Host identifiers"
            security = "zero-trust-assessment:read"
            produces = "application/json"
            parameters = @{
                ids = @{
                    description = "One or more Host identifiers"
                    pattern = "\w{32}"
                    required = $true
                    type = 'array'
                }
            }
            responses = @{
                default = "domain.AssessmentsResponse"
                "msa.ReplyMetaOnly" = @(400,403,429)
            }
        }
    }
}
