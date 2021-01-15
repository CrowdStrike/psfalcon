@{
    "/oauth2/revoke" = @{
        post = @{
            description = "Revoke your current OAuth2 access token and clear cached API credentials"
            consumes = "application/x-www-form-urlencoded"
            produces = "application/json"
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,429,500)
                default = "msa.ReplyMetaOnly"
            }
        }
    }
    "/oauth2/token" = @{
        post = @{
            description = "Request an OAuth2 access token"
            consumes = "application/x-www-form-urlencoded"
            produces = "application/json"
            parameters = @{
                client_id = @{}
                client_secret = @{}
                cloud = @{
                    enum = @(
                        "eu-1"
                        "us-gov-1"
                        "us-1"
                        "us-2"
                    )
                    description = "Destination cloud"
                    position = 3
                }
                member_cid = @{}
            }
            responses = @{
                "domain.AccessTokenResponseV1" = @(201)
                "msa.ReplyMetaOnly" = @(400,403,500)
            }
        }
    }
}