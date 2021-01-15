@{
    "/incidents/combined/crowdscores/v1" = @{
        get = @{
            description = "Search for CrowdScore values"
            security = "incidents:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("score.asc","score.desc","timestamp.asc","timestamp.desc")
                }
            }
            responses = @{
                "api.MsaEnvironmentScoreResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.MsaEnvironmentScoreResponse"
            }
        }
    }
    "/incidents/entities/behaviors/GET/v1" = @{
        post = @{
            description = "Get detailed information about {0} identifiers"
            security = "incidents:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "msa.IdsRequest"
            }
            responses = @{
                "api.MsaExternalBehaviorResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.MsaExternalBehaviorResponse"
            }
        }
    }
    "/incidents/entities/incident-actions/v1" = @{
        post = @{
            description = "Perform actions on {0}s"
            security = "incidents:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "EntityAction"
                update_detects = @{
                    description = "Update status of related 'new' detections"
                    type = "boolean"
                    in = "query"
                    required = $false
                    position = 4
                  }
                  overwrite_detects = @{
                    description = "Replace existing status for related detections"
                    type = "boolean"
                    in = "query"
                    required = $false
                    position = 5
                  }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,409,429,500)
                default = "msa.ReplyMetaOnly"
            }
        }
    }
    "/incidents/entities/incidents/GET/v1" = @{
        post = @{
            description = "Retrieve detailed information about {0} identifiers"
            security = "incidents:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "msa.IdsRequest"
            }
            responses = @{
                "api.MsaExternalIncidentResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.MsaExternalIncidentResponse"
            }
        }
    }
    "/incidents/queries/behaviors/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "incidents:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("timestamp.asc","timestamp.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "msa.QueryResponse"
            }
        }
    }
    "/incidents/queries/incidents/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "incidents:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("assigned_to.asc","assigned_to.desc","assigned_to_name.asc","assigned_to_name.desc",
                        "end.asc","end.desc","modified_timestamp.asc","modified_timestamp.desc","name.asc",
                        "name.desc","sort_score.asc","sort_score.desc","start.asc","start.desc","state.asc",
                        "state.desc","status.asc","status.desc")
                }
            }
            responses = @{
                "api.MsaIncidentQueryResponse" = @(200)
                "msa.ReplyMetaOnly" = @(400,403,429,500)
                default = "api.MsaIncidentQueryResponse"
            }
        }
    }
}