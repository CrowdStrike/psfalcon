@{
    "/processes/entities/processes/v1" = @{
        get = @{
            description = "Retrieve summary information about {0}es"
            security = "iocs:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "api.MsaProcessDetailResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "api.MsaProcessDetailResponse"
            }
        }
    }
}