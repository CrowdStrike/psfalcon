@{
    "/policy/combined/device-control-members/v1" = @{
        get = @{
            description = "Search for detailed {0} member information"
            security = "device-control-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "responses.PolicyMembersRespV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PolicyMembersRespV1"
            }
        }
    }
    "/policy/combined/device-control/v1" = @{
        get = @{
            description = "Search for detailed {0} information"
            security = "device-control-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "responses.DeviceControlPoliciesV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.DeviceControlPoliciesV1"
            }
        }
    }
    "/policy/combined/firewall-members/v1" = @{
        get = @{
            description = "Search for detailed {0} member information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "responses.PolicyMembersRespV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PolicyMembersRespV1"
            }
        }
    }
    "/policy/combined/firewall/v1" = @{
        get = @{
            description = "Search for detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "responses.FirewallPoliciesV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.FirewallPoliciesV1"
            }
        }
    }
    "/policy/combined/prevention-members/v1" = @{
        get = @{
            description = "Search for detailed {0} member information"
            security = "prevention-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "responses.PolicyMembersRespV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PolicyMembersRespV1"
            }
        }
    }
    "/policy/combined/prevention/v1" = @{
        get = @{
            description = "Search for detailed {0} information"
            security = "prevention-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "responses.PreventionPoliciesV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PreventionPoliciesV1"
            }
        }
    }
    "/policy/combined/response-members/v1" = @{
        get = @{
            description = "Search for detailed {0} member information"
            security = "response-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                default = ""
            }
        }
    }
    "/policy/combined/response/v1" = @{
        get = @{
            description = "Search for detailed {0} information"
            security = "response-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                default = ""
            }
        }
    }
    "/policy/combined/reveal-uninstall-token/v1" = @{
        post = @{
            description = "Retrieve an uninstall or maintenance token"
            security = "sensor-update-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.RevealUninstallTokenV1"
            }
            responses = @{
                "responses.RevealUninstallTokenRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.RevealUninstallTokenRespV1"
            }
        }
    }
    "/policy/combined/sensor-update-builds/v1" = @{
        get = @{
            description = "Search for {0} build versions"
            security = "sensor-update-policies:read"
            produces = "application/json"
            parameters = @{
                platform = @{
                    enum = @("linux","mac","windows")
                    in = "query"
                    position = 1
                }
            }
            responses = @{
                "responses.SensorUpdateBuildsV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SensorUpdateBuildsV1"
            }
        }
    }
    "/policy/combined/sensor-update-members/v1" = @{
        get = @{
            description = "Search for detailed {0} member information"
            security = "sensor-update-policies:read"
            produces = "application/json"
            parameters = @{
                parameters = @{
                    schema = "BasicParamsId"
                }
            }
            responses = @{
                "responses.PolicyMembersRespV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PolicyMembersRespV1"
            }
        }
    }
    "/policy/combined/sensor-update/v2" = @{
        get = @{
            description = "Search for detailed {0} information"
            security = "sensor-update-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "responses.SensorUpdatePoliciesV2" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SensorUpdatePoliciesV2"
            }
        }
    }
    "/policy/entities/device-control-actions/v1" = @{
        post = @{
            description = "Perform {0} actions"
            security = "device-control-policies:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("add-host-group","remove-host-group","enable","disable")
                }
                ids = @{
                    dynamic = "Id"
                    description = "{0} identifier"
                    in = "body"
                    type = "string"
                    required = $true
                    position = 2
                }
                value = @{
                    dynamic = "GroupId"
                    description = "Host Group identifier"
                    type = "string"
                    in = "body"
                    parent = "action_parameters"
                    pattern = "\w{32}"
                    required = $false
                    position = 3
                }
            }
            responses = @{
                "responses.DeviceControlPoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.DeviceControlPoliciesV1"
            }
        }
    }
    "/policy/entities/device-control-precedence/v1" = @{
        post = @{
            description = "Set {0} precedence"
            security = "device-control-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyPrecedence"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/entities/device-control/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "device-control-policies:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.DeviceControlPoliciesV1" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.DeviceControlPoliciesV1"
            }
        }
        post = @{
            description = "Create Device Control policies"
            security = "device-control-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyCreate"
            }
            responses = @{
                "responses.DeviceControlPoliciesV1" = @(201,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        delete = @{
            description = "Remove Device Control policies"
            security = "device-control-policies:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify Device Control policies"
            security = "device-control-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyUpdate"
            }
            responses = @{
                "responses.DeviceControlPoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.DeviceControlPoliciesV1"
            }
        }
    }
    "/policy/entities/firewall-actions/v1" = @{
        post = @{
            description = "Perform {0} actions"
            security = "firewall-management:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("add-host-group","remove-host-group","enable","disable")
                }
                ids = @{
                    dynamic = "Id"
                    description = "{0} identifier"
                    in = "body"
                    type = "string"
                    required = $true
                    position = 2
                }
                value = @{
                    dynamic = "GroupId"
                    description = "Host Group identifier"
                    type = "string"
                    in = "body"
                    parent = "action_parameters"
                    pattern = "\w{32}"
                    required = $false
                    position = 3
                }
            }
            responses = @{
                "responses.FirewallPoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.FirewallPoliciesV1"
            }
        }
    }
    "/policy/entities/firewall-precedence/v1" = @{
        post = @{
            description = "Set {0} precedence"
            security = "firewall-management:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyPrecedence"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/entities/firewall/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.FirewallPoliciesV1" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.FirewallPoliciesV1"
            }
        }
        post = @{
            description = "Create Firewall policies"
            security = "firewall-management:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.CreateFirewallPoliciesV1"
            }
            responses = @{
                "responses.FirewallPoliciesV1" = @(201,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        delete = @{
            description = "Remove Firewall policies"
            security = "firewall-management:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify Firewall policies"
            security = "firewall-management:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.UpdateFirewallPoliciesV1"
            }
            responses = @{
                "responses.FirewallPoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.FirewallPoliciesV1"
            }
        }
    }
    "/policy/entities/ioa-exclusions/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "self-service-ioa-exclusions:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.IoaExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.IoaExclusionRespV1"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "self-service-ioa-exclusions:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
                comment = @{
                    position = 2
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "self-service-ioa-exclusions:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.IoaExclusionUpdateReqV1"
            }
            responses = @{
                "responses.IoaExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.IoaExclusionRespV1"
            }
        }
    }
    "/policy/entities/ml-exclusions/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "ml-exclusions:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.MlExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.MlExclusionRespV1"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "ml-exclusions:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.MlExclusionCreateReqV1"
            }
            responses = @{
                "responses.MlExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.MlExclusionRespV1"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "ml-exclusions:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
                comment = @{
                    position = 2
                }
            }
            responses = @{
                "responses.MlExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.MlExclusionRespV1"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "ml-exclusions:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.SvExclusionUpdateReqV1"
            }
            responses = @{
                "responses.MlExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.MlExclusionRespV1"
            }
        }
    }
    "/policy/entities/prevention-actions/v1" = @{
        post = @{
            description = "Perform {0} actions"
            security = "prevention-policies:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("add-host-group","remove-host-group","enable","disable")
                }
                ids = @{
                    dynamic = "Id"
                    description = "{0} identifier"
                    in = "body"
                    type = "string"
                    required = $true
                    position = 2
                }
                value = @{
                    dynamic = "GroupId"
                    description = "Host Group identifier"
                    type = "string"
                    in = "body"
                    parent = "action_parameters"
                    pattern = "\w{32}"
                    required = $false
                    position = 3
                }
            }
            responses = @{
                "responses.PreventionPoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PreventionPoliciesV1"
            }
        }
    }
    "/policy/entities/prevention-precedence/v1" = @{
        post = @{
            description = "Set {0} precedence"
            security = "prevention-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyPrecedence"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/entities/prevention/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "prevention-policies:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.PreventionPoliciesV1" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PreventionPoliciesV1"
            }
        }
        post = @{
            description = "Create Prevention policies"
            security = "prevention-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyCreate"
            }
            responses = @{
                "responses.PreventionPoliciesV1" = @(201,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        delete = @{
            description = "Remove Prevention policies"
            security = "prevention-policies:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify Prevention policies"
            security = "prevention-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyUpdate"
            }
            responses = @{
                "responses.PreventionPoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.PreventionPoliciesV1"
            }
        }
    }
    "/policy/entities/response-actions/v1" = @{
        post = @{
            description = "Perform {0} actions"
            security = "response-policies:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("add-host-group","remove-host-group","enable","disable")
                }
                ids = @{
                    dynamic = "Id"
                    description = "{0} identifier"
                    in = "body"
                    type = "string"
                    required = $true
                    position = 2
                }
                value = @{
                    dynamic = "GroupId"
                    description = "Host Group identifier"
                    type = "string"
                    in = "body"
                    parent = "action_parameters"
                    pattern = "\w{32}"
                    required = $false
                    position = 3
                }
            }
            responses = @{
                default = ""
            }
        }
    }
    "/policy/entities/response-precedence/v1" = @{
        post = @{
            description = "Set {0} precedence"
            security = "response-policies:write"
            produces = "application/json"
            parameters = @{
                schema = ""
            }
            responses = @{
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/entities/response/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "response-policies:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                default = ""
            }
        }
        post = @{
            description = "Create Response policies"
            security = "response-policies:write"
            produces = "application/json"
            parameters = @{
                schema = ""
            }
            responses = @{}
        }
        delete = @{
            description = "Remove Response policies"
            security = "response-policies:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify Response policies"
            security = "response-policies:write"
            produces = "application/json"
            parameters = @{
                schema = ""
            }
            responses = @{
                default = ""
            }
        }
    }
    "/policy/entities/sensor-update-actions/v1" = @{
        post = @{
            description = "Perform {0} actions"
            security = "sensor-update-policies:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                action_name = @{
                    enum = @("add-host-group","remove-host-group","enable","disable")
                }
                ids = @{
                    dynamic = "Id"
                    description = "{0} identifier"
                    in = "body"
                    type = "string"
                    required = $true
                    position = 2
                }
                value = @{
                    dynamic = "GroupId"
                    description = "Host Group identifier"
                    type = "string"
                    in = "body"
                    parent = "action_parameters"
                    pattern = "\w{32}"
                    required = $false
                    position = 3
                }
            }
            responses = @{
                "responses.SensorUpdatePoliciesV1" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SensorUpdatePoliciesV1"
            }
        }
    }
    "/policy/entities/sensor-update-precedence/v1" = @{
        post = @{
            description = "Set {0} precedence"
            security = "sensor-update-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyPrecedence"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/entities/sensor-update/v1" = @{
        delete = @{
            description = "Remove Sensor Update policies"
            security = "sensor-update-policies:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/entities/sensor-update/v2" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "sensor-update-policies:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.SensorUpdatePoliciesV2" = @(200,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SensorUpdatePoliciesV2"
            }
        }
        post = @{
            description = "Create Sensor Update policies"
            security = "sensor-update-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.CreateSensorUpdatePoliciesV2"
            }
            responses = @{
                "responses.SensorUpdatePoliciesV2" = @(201,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
        patch = @{
            description = "Modify Sensor Update policies"
            security = "sensor-update-policies:write"
            produces = "application/json"
            parameters = @{
                schema = "PolicyUpdate"
            }
            responses = @{
                "responses.SensorUpdatePoliciesV2" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SensorUpdatePoliciesV2"
            }
        }
    }
    "/policy/entities/sv-exclusions/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "sensor-visibility-exclusions:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "responses.SvExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SvExclusionRespV1"
            }
        }
        post = @{
            description = "Create {0}s"
            security = "sensor-visibility-exclusions:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.SvExclusionCreateReqV1"
            }
            responses = @{
                "responses.MlExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.MlExclusionRespV1"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "sensor-visibility-exclusions:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
                comment = @{
                    position = 2
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "sensor-visibility-exclusions:write"
            produces = "application/json"
            parameters = @{
                schema = "requests.SvExclusionUpdateReqV1"
            }
            responses = @{
                "responses.SvExclusionRespV1" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "responses.SvExclusionRespV1"
            }
        }
    }
    "/policy/queries/device-control-members/v1" = @{
        get = @{
            description = "Search for {0} members"
            security = "device-control-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/device-control/v1" = @{
        get = @{
            description = "Search for Device Control policies"
            security = "device-control-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/firewall-members/v1" = @{
        get = @{
            description = "Search for {0} members"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/firewall/v1" = @{
        get = @{
            description = "Search for Firewall policies"
            security = "firewall-management:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/ioa-exclusions/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "self-service-ioa-exclusions:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("applied_globally.asc","applied_globally.desc","created_by.asc","created_by.desc",
                        "created_on.asc","created_on.desc","last_modified.asc","last_modified.desc",
                        "modified_by.asc","modified_by.desc","name.asc","name.desc","pattern_id.asc",
                        "pattern_id.desc","pattern_name.asc","pattern_name.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/ml-exclusions/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "ml-exclusions:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("applied_globally.asc","applied_globally.desc","created_by.asc","created_by.desc",
                        "created_on.asc","created_on.desc","last_modified.asc","last_modified.desc",
                        "modified_by.asc","modified_by.desc","value.asc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/prevention-members/v1" = @{
        get = @{
            description = "Search for {0} members"
            security = "prevention-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/prevention/v1" = @{
        get = @{
            description = "Search for Prevention policies"
            security = "prevention-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/response-members/v1" = @{
        get = @{
            description = "Search for {0} members"
            security = "response-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/response/v1" = @{
        get = @{
            description = "Search for Response policies"
            security = "response-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
            }
            responses = @{
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/sensor-update-members/v1" = @{
        get = @{
            description = "Search for {0} members"
            security = "sensor-update-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsId"
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/sensor-update/v1" = @{
        get = @{
            description = "Search for Sensor Update policies"
            security = "sensor-update-policies:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("created_by.asc","created_by.desc","created_timestamp.asc","created_timestamp.desc",
                        "enabled.asc","enabled.desc","modified_by.asc","modified_by.desc","modified_timestamp.asc",
                        "modified_timestamp.desc","name.asc","name.desc","platform_name.asc","platform_name.desc",
                        "precedence.asc","precedence.desc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/policy/queries/sv-exclusions/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "sensor-visibility-exclusions:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                sort = @{
                    enum = @("applied_globally.asc","applied_globally.desc","created_by.asc","created_by.desc",
                        "created_on.asc","created_on.desc","last_modified.asc","last_modified.desc",
                        "modified_by.asc","modified_by.desc","value.asc")
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
}