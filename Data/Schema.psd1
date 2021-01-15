@{
    # Sets of parameters that are re-used by API endpoints
    AWSAccount = @{
        id = @{
            parent = "resources"
            description = "{0} identifier"
        }
        iam_role_arn = @{
            parent = "resources"
            description = "Full ARN of the IAM role created in the {0} to control access"
        }
        external_id = @{
            parent = "resources"
            description = "{0} identifier with cross-account IAM role access"
            pattern = "\d{12}"
        }
        cloudtrail_bucket_owner_id = @{
            parent = "resources"
            description = "AWS account identifier containing cloudtrail logs"
            pattern = "\d{12}"
        }
        cloudtrail_bucket_region = @{
            parent = "resources"
            description = "AWS region where the account containing cloudtrail logs resides"
        }
        rate_limit_time = @{
            parent = "resources"
            description = "Number of seconds between requests defined by 'RateLimitReqs'"
            type = "int64"
        }
        rate_limit_reqs = @{
            parent = "resources"
            description = "Maximum number of requests within 'RateLimitTime'"
            type = "integer"
        }
    }
    BasicParams = @{
        filter = @{
            description = "Falcon Query Language expression to limit results"
            in = "query"
            position = 1
        }
        sort = @{
            description = "Property and direction to sort results"
            in = "query"
            position = 2
        }
        limit = @{
            description = "Maximum number of results per request"
            type = "integer"
            in = "query"
            min = 1
            max = 5000
            position = 3
        }
        offset = @{
            description = "Position to begin retrieving results"
            type = "integer"
            in = "query"
            position = 4
        }
    }
    BasicParamsId = @{
        id = @{
            description = "{0} identifier"
            in = "query"
            position = 1
        }
        filter = @{
            description = "Falcon Query Language expression to limit results"
            in = "query"
            position = 2
        }
        sort = @{
            description = "Property and direction to sort results"
            in = "query"
            position = 3
        }
        limit = @{
            description = "Maximum number of results per request"
            type = "integer"
            in = "query"
            min = 1
            max = 5000
            position = 4
        }
        offset = @{
            description = "Position to begin retrieving results"
            type = "integer"
            in = "query"
            position = 5
        }
    }
    BasicParamsQuery = @{
        filter = @{
            description = "Falcon Query Language expression to limit results"
            in = "query"
            position = 1
        }
        q = @{
            description = "Perform a generic substring search across available fields"
            dynamic = "Query"
            in = "query"
            position = 2
        }
        sort = @{
            description = "Property and direction to sort results"
            in = "query"
            position = 3
        }
        limit = @{
            description = "Maximum number of results per request"
            type = "integer"
            in = "query"
            min = 1
            max = 5000
            position = 4
        }
        offset = @{
            description = "Position to begin retrieving results"
            type = "integer"
            in = "query"
            position = 5
        }
    }
    EntityAction = @{
        name = @{
            description = "Action to perform"
            enum = @("add_tag","delete_tag","update_description","update_name","update_status")
            parent = "action_parameters"
            required = $true
            position = 1
        }
        value = @{
            description = "Value for the chosen action"
            parent = "action_parameters"
            required = $true
            position = 2
        }
        ids = @{
            description = "One or more {0} identifiers"
            type = "array"
            required = $true
            position = 3
        }
    }
    PolicyCreate = @{
        platform_name = @{
            description = "Operating System platform"
            parent = "resources"
            required = $true
            enum = @("Windows","Mac","Linux")
            position = 1
        }
        name = @{
            description = "{0} name"
            parent = "resources"
            required = $true
            position = 2
        }
        settings = @{
            description = "An array of {0} settings"
            parent = "resources"
            type = "array"
            position = 3
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 4
        }
        clone_id = @{
            description = "Clone an existing {0}"
            parent = "resources"
            position = 5
            pattern = "\w{32}"
        }
    }
    PolicyPrecedence = @{
        platform_name = @{
            description = "Operating System platform"
            required = $true
            enum = @("Windows","Mac","Linux")
            position = 1
        }
        ids = @{
            description = "All policy identifiers in your account, in desired precedence order"
            type = "array"
            required = $true
            position = 2
        }
    }
    PolicyUpdate = @{
        id = @{
            required = $true
            description = "{0} identifier"
            parent = "resources"
            position = 1
        }
        name = @{
            description = "{0} name"
            parent = "resources"
            required = $true
            position = 2
        }
        settings = @{
            description = "An array of {0} settings"
            parent = "resources"
            type = "array"
            position = 3
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 4
        }
    }
    RtrCmdStatus = @{
        cloud_request_id = @{
            description = "{0} request identifier"
            in = "query"
            required = $true
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            position = 1
        }
        sequence_id = @{
            description = "Sequence identifier"
            type = "integer"
            in = "query"
            position = 2
        }
    }
    RtrScript = @{
        file = @{
            dynamic = "Path"
            type = "string"
            in = "formData"
            required = $true
            script = '[System.IO.Path]::IsPathRooted($_)'
            scripterror = "Relative paths are not permitted."
            description = "Local path to script file"
            position = 1
        }
        permission_type = @{
            in = "formData"
            required = $true
            enum = @("private","group","public")
            description = "{0} permission level"
            position = 2
        }
        platform = @{
            description = "Operating System platform"
            enum = @("windows","mac","linux")
            type = "string"
            in = "formData"
            required = $true
            position = 3
        }
        name = @{
            description = "{0} name"
            in = "formData"
            position = 4
        }
        description = @{
            description = "{0} description"
            in = "formData"
            position = 5
        }
        comments_for_audit_log = @{
            dynamic = "Comment"
            description = "Audit log comment"
            max = 4096
            in = "formData"
            position = 6
        }
    }
    # Swagger-defined Schema, used to create dynamic parameters
    "api.IOCViewRecord" = @{
        policy = @{
            description = "Action to perform when the {0} is observed by a Host"
            enum = @("detect","none")
            position = 2
        }
        share_level = @{
            description = "{0} visibility level"
            enum = @("red")
            position = 3
        }
        expiration_days = @{
            description = "Number of days before expiration (for 'domain' 'ipv4' and 'ipv6')"
            type = "int32"
            position = 4
        }
        source = @{
            description = "{0} source"
            position = 5
        }
        description = @{
            description = "{0} description"
            position = 6
        }
    }
    "api.RuleCreateV1" = @{
        rulegroup_id = @{
            description = "Custom IOA Rule Group identifier"
            required = $true
            position = 1
        }
        name = @{
            description = "{0} name"
            required = $true
            position = 2
        }
        pattern_severity = @{
            description = "{0} severity"
            enum = @("critical","high","medium","low","informational")
            required = $true
            position = 3
        }
        ruletype_id = @{
            description = "{0} type identifier"
            enum = @(1,2,5,6,9,10,11,12)
            required = $true
            position = 4
        }
        disposition_id = @{
            description = "Action to perform"
            type = "int32"
            enum = @(10,20,30)
            required = $true
            position = 5
        }
        field_values = @{
            description = "An array of {0} properties"
            type = "array"
            required = $true
            position = 6
        }
        description = @{
            description = "{0} description"
            position = 7
        }
        comment = @{
            description = "Audit log comment"
            position = 8
        }
    }
    "api.RulesGetRequestV1" = @{
        ids = @{
            type = "array"
            required = $true
        }
    }
    "api.RuleGroupCreateRequestV1" = @{
        platform = @{
            description = "Operating System platform"
            enum = @("windows","mac","linux")
            required = $true
            position = 1
        }
        name = @{
            description = "{0} name"
            required = $true
            position = 2
        }
        description = @{
            description = "{0} description"
            position = 3
        }
        comment = @{
            description = "Audit log comment"
            position = 4
        }
    }
    "api.RuleGroupModifyRequestV1" = @{
        id = @{
            description = "{0} identifier"
            required = $true
            position = 1
        }
        name = @{
            description = "{0} name"
            required = $true
            position = 2
        }
        enabled = @{
            description = "{0} status"
            required = $true
            type = "boolean"
            position = 3

        }
        rulegroup_version = @{
            description = "{0} version"
            type = "int64"
            required = $true
            position = 4
        }
        description = @{
            description = "{0} description"
            required = $true
            position = 5
        }
        comment = @{
            description = "Audit log comment"
            required = $true
            position = 6
        }
    }
    "api.RuleUpdatesRequestV1" = @{
        rulegroup_id = @{
            description = "{0} identifier"
            required = $true
            position = 1
        }
        rulegroup_version = @{
            description = "{0} version"
            type = "int64"
            required = $true
            position = 2
        }
        rule_updates = @{
            description = "An array of {0} properties"
            type = "array"
            position = 3
        }
        comment = @{
            description = "Audit log comment"
            position = 4
        }
    }
    "api.tokenCreateRequestV1" = @{
        label = @{
            description = "{0} label"
            position = 1
        }
        expires_timestamp = @{
            description = "{0} expiration time (RFC-3339) or 'Null' if the token will never expire"
            position = 2
        }
    }
    "api.tokenPatchRequestV1" = @{
        label = @{
            description = "{0} label"
            position = 2
        }
        expires_timestamp = @{
            description = "{0} expiration time (RFC-3339) or 'Null' if the token will never expire"
            position = 3
        }
        revoked = @{
            description = "Set revocation status of the {0}"
            type = "boolean"
            position = 4
        }
    }
    "domain.BatchExecuteCommandRequest" = @{
        base_command = @{
            dynamic = "Command"
            description = "Real-time Response command"
            required = $true
            position = 1
        }
        command_string = @{
            dynamic = "Arguments"
            description = "Arguments to include with the command"
            position = 2
        }
        batch_id = @{
            description = "Batch Real-time Response session identifier"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            required = $true
            position = 3
        }
        optional_hosts = @{
            dynamic = "OptionalHostIds"
            description = "Restrict execution to specific Host identifiers"
            type = "array"
            pattern = "\w{32}"
            position = 4
        }
    }
    "domain.BatchGetCommandRequest" = @{
        file_path = @{
            description = "Path to file on target Host(s)"
            position = 1
            required = $true
        }
        batch_id = @{
            description = "Batch Real-time Response session identifier"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            required = $true
            position = 2
        }
        optional_hosts = @{
            dynamic = "OptionalHostIds"
            description = "Restrict command execution to specific Host identifiers"
            type = "array"
            pattern = "\w{32}"
            position = 3
        }
    }
    "domain.BatchInitSessionRequest" = @{
        host_ids = @{
            description = "Host identifier(s)"
            type = "array"
            pattern = "\w{32}"
            required = $true
            position = 1
        }
        queue_offline = @{
            description = "Add non-responsive Hosts to the offline queue"
            type = "boolean"
            position = 2
        }
        existing_batch_id = @{
            description = "Add Hosts to an existing {0}"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            position = 3
        }
    }
    "domain.BatchRefreshSessionRequest" = @{
        batch_id = @{
            description = "{0} identifier"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            position = 1
            required = $true
        }
        hosts_to_remove = @{
            type = "array"
            description = "Host identifiers to remove from the {0}"
            position = 2
            pattern = "\w{32}"
        }
    }
    "domain.CommandExecuteRequest" = @{
        base_command = @{
            dynamic = "Command"
            description = "Real-time Response command"
            required = $true
            position = 1
        }
        command_string = @{
            dynamic = "Arguments"
            description = "Arguments to include with the command"
            position = 2
        }
        session_id = @{
            description = "Real-time Response session identifier"
            position = 3
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            required = $true
        }
    }
    "domain.DetectsEntitiesPatchRequest" = @{
        ids = @{
            description = "One or more {0} identifiers"
            type = "array"
            position = 1
        }
        status = @{
            description = "{0} status"
            enum = @("new","in_progress","true_positive","false_positive","ignored","closed","reopened")
            position = 2
        }
        assigned_to_uuid = @{
            description = "User identifier for assignment"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            position = 3
        }
        comment = @{
            description = "{0} comment"
            position = 4
        }
        show_in_ui = @{
            description = "Visible within the Falcon UI [default: `$true]"
            type = "boolean"
            position = 5
        }
    }
    "domain.InitRequest" = @{
        device_id = @{
            dynamic = "HostId"
            description = "Host identifier"
            pattern = "\w{32}"
            required = $true
            position = 1
        }
        queue_offline = @{
            description = "Add Host to the offline queue if it does not respond"
            type = "boolean"
            position = 2
        }
    }
    "domain.RoleIDs" = @{
        roleIds = @{
            dynamic = "Ids"
            type = "array"
            required = $true
            position = 1
            description = "One or more {0} identifiers"
        }
    }
    "domain.UpdateUserFields" = @{
        firstName = @{
            dynamic = "FirstName"
            description = "First name"
            position = 2
        }
        lastName = @{
            dynamic = "LastName"
            description = "Last name"
            position = 3
        }
    }
    "domain.UserCreateRequest" = @{
        uid = @{
            dynamic = "Username"
            position = 1
            description = "Username (typically an email address)"
            required = $true
        }
        firstName = @{
            dynamic = "FirstName"
            description = "First name"
            position = 2
        }
        lastName = @{
            dynamic = "LastName"
            description = "Last name"
            position = 3
        }
        password = @{
            description = "If left blank, the user will be emailed a link to set their password (recommended)"
            position = 4
        }
    }
    "falconx.SubmissionParametersV1" = @{
        environment_id = @{
            description = "Analysis environment"
            enum = @("android","ubuntu16_x64","win7_x64","win7_x86","win10_x64")
            parent = "sandbox"
            required = $true
        }
        sha256 = @{
            description = "Hash value of the sample to analyze"
            parent = "sandbox"
            pattern = "\w{64}"
        }
        url = @{
            description = "A webpage or file URL"
            parent = "sandbox"
        }
        submit_name = @{
            description = "Name of sample being submitted"
            parent = "sandbox"
        }
        command_line = @{
            description = "Command line script passed to the submitted file at runtime"
            parent = "sandbox"
        }
        action_script = @{
            description = "Runtime script for sandbox analysis"
            enum = @("default","default_maxantievasion","default_randomfiles","default_randomtheme",
                "default_openie")
            parent = "sandbox"
        }
        document_password = @{
            description = "Auto-filled for Adobe or Office files that prompt for a password"
            parent = "sandbox"
        }
        enable_tor = @{
            description = "Route traffic via TOR"
            parent = "sandbox"
            type = "boolean"
        }
        system_date = @{
            description = "A custom date to use in the analysis environment"
            pattern = "\d{4}-\d{2}-\d{2}"
            parent = "sandbox"
        }
        system_time = @{
            description = "A custom time to use in the analysis environment"
            pattern = "\d{2}:\d{2}"
            parent = "sandbox"
        }
        user_tags = @{
            description = "Tags to categorize the submission"
            type = "array"
        }
    }
    "fwmgr.api.RuleCreateRequestV1" = @{
        name = @{
            required = $true
        }
        direction = @{
            required = $true
        }
        remote_port = @{
            end = @{
                required = $true
                type = "integer"
            }
            start = @{
                required = $true
                type = "integer"
            }
        }
        address_family = @{
            required = $true
        }
        enabled = @{
            required = $true
            type = "boolean"
        }
        action = @{
            required = $true
        }
        platform_ids = @{
            type = "array"
            required = $true
        }
        log = @{
            required = $true
            type = "boolean"
        }
        description = @{
            required = $true
        }
        fields = @{
            label = @{}
            value = @{}
            final_value = @{}
            type = @{}
            values = @{
                type = "array"
            }
            name = @{
                required = $true
            }
        }
        protocol = @{
            required = $true
        }
        temp_id = @{
            required = $true
        }
        local_address = @{
            netmask = @{
                type = "byte"
            }
            address = @{
                required = $true
            }
        }
        remote_address = @{
            netmask = @{
                type = "byte"
            }
            address = @{
                required = $true
            }
        }
        icmp = @{
            icmp_code = @{
                required = $true
            }
            icmp_type = @{
                required = $true
            }
        }
        monitor = @{
            count = @{
                required = $true
            }
            period_ms = @{
                required = $true
            }
        }
        local_port = @{
            end = @{
                required = $true
                type = "integer"
            }
            start = @{
                required = $true
                type = "integer"
            }
        }
    }
    "malquery.FuzzySearchParametersV1" = @{
        patterns = @{
            schema = "malquery.SearchParameter"
        }
        options = @{
            schema = "malquery.FuzzyOptions"
        }
    }
    "malquery.SearchParameter" = @{
        type = @{
            description = "Pattern type"
            enum = @("hex","ascii","wide")
            required = $true
        }
        value = @{
            description = "Pattern value"
            required = $true
        }
    }
    "malquery.ExternalExactSearchParametersV1" = @{
        patterns = @{
            schema = "malquery.SearchParameter"
        }
        options = @{
            schema = "malquery.ExternalHuntOptions"
        }
    }
    "malquery.ExternalHuntOptions" = @{
        filter_meta = @{
            description = "Subset of metadata fields to include in the result"
            type = "array"
            enum = @("sha256","md5","type","size","first_seen","label","family")
        }
        filter_filetypes = @{
            description = "File types to include with the result"
            type = "array"
            enum = @("cdf","cdfv2","cjava","dalvik","doc","docx","elf32","elf64","email","html","hwp","java.arc",
                "lnk","macho","pcap","pdf","pe32","pe64","perl","ppt","pptx","python","pythonc","rtf","swf",
                "text","xls","xlsx")
        }
        min_date = @{
            description = "Limit results to files first seen after this date"
            pattern = "\d{4}/\d{2}/\d{2}"
        }
        max_date = @{
            description = "Limit results to files first seen after this date"
            pattern = "\d{4}/\d{2}/\d{2}"
        }
        min_size = @{
            description = "Minimum file size specified in bytes or multiples of KB/MB/GB"
        }
        max_size = @{
            description = "Maximum file size specified in bytes or multiples of KB/MB/GB"
        }
        limit = @{
            description = "Maximum number of results to include in the result"
            type = "int32"
        }
    }
    "malquery.ExternalHuntParametersV1" = @{
        yara_rule = @{
            description = "YARA rule"
            required = $true
        }
        options = @{
            schema = "malquery.ExternalHuntOptions"
        }
    }
    "malquery.FuzzyOptions" = @{
        filter_meta = @{
            description = "Subset of metadata fields to include in the result"
            type = "array"
            enum = @("sha256","md5","type","size","first_seen","label","family")
        }
        limit = @{
            description = "Maximum number of results to include in the result"
            type = "int32"
        }
    }
    "malquery.MultiDownloadRequestV1" = @{
        samples = @{
            description = "One or more Sha256 hash values"
            type = "array"
            required = $true
            position = 1
        }
    }
    "mlscanner.SamplesScanParameters" = @{
        samples = @{
            description = "One or more Sha256 hash values"
            type = "array"
            required = $true
            position = 1
        }
    }
    "models.ModifyAWSCustomerSettingsV1" = @{
        cloudtrail_bucket_owner_id = @{
            parent = "resources"
            description = "AWS account identifier containing cloudtrail logs"
            pattern = "\d{12}"
            position = 1
        }
        static_external_id = @{
            parent = "resources"
            description = "Default external identifier to apply to AWS accounts"
            position = 2
        }
    }
    "msa.IdsRequest" = @{
        ids = @{
            description = "One or more {0} identifiers"
            type = "array"
            position = 1
            required = $true
        }
    }
    "registration.AWSAccountCreateRequestExtV2" = @{
        account_id = @{
            description = "{0} identifier"
            parent = "resources"
            pattern = "\d{12}"
            required = $true
            position = 1
        }
        organization_id = @{
            description = "AWS organization identifier"
            parent = "resources"
            pattern = "\d{12}"
            position = 2
        }
    }
    "registration.AzureAccountCreateRequestExternalV1" = @{
        subscription_id = @{
            description = "Azure subscription identifier"
            parent = "resources"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            position = 1
        }
        tenant_id = @{
            description = "Azure tenant identifier"
            parent = "resources"
            pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
            position = 2
        }
    }
    "registration.GCPAccountCreateRequestExtV1" = @{
        parent_id = @{
            description = "GCP project identifier"
            type = "array"
            parent = "resources"
            pattern = "\d{12}"
            required = $true
            position = 1
        }
    }
    "registration.PolicyRequestExtV1" = @{
        policy_id = @{
            description = "Policy identifier"
            type = "int32"
            parent = "resources"
            required = $true
            position = 1
        }
        enabled = @{
            description = "Status"
            parent = "resources"
            type = "boolean"
            required = $true
            position = 2
        }
        severity = @{
            description = "Severity level"
            enum = @("high","medium","informational")
            parent = "resources"
            required = $true
            position = 3
        }
    }
    "registration.ScanScheduleUpdateRequestV1" = @{
        cloud_platform = @{
            description = "Cloud platform"
            enum = @("aws","azure","gcp")
            parent = "resources"
            required = $true
        }
        scan_schedule = @{
            description = "Scan interval"
            enum = @("2h","6h","12h","24h")
            parent = "resources"
            required = $true
        }
    }
    "requests.CreateFirewallPoliciesV1" = @{
        platform_name = @{
            description = "Operating System platform"
            parent = "resources"
            required = $true
            enum = @("Windows","Mac","Linux")
            position = 1
        }
        name = @{
            description = "{0} name"
            parent = "resources"
            required = $true
            position = 2
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 3
        }
        clone_id = @{
            description = "Clone an existing {0}"
            parent = "resources"
            position = 4
            pattern = "\w{32}"
        }
    }
    "requests.CreateGroupsV1" = @{
        group_type = @{
            description = "{0} type"
            required = $true
            parent = "resources"
            enum = @("static","dynamic")
            position = 1
        }
        name = @{
            description = "{0} name"
            required = $true
            parent = "resources"
            position = 2
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 3
        }
        assignment_rule = @{
            description = "Assignment rule for 'dynamic' {0}s"
            parent = "resources"
            position = 4
        }
    }
    "requests.CreateSensorUpdatePoliciesV2" = @{
        platform_name = @{
            description = "Operating System platform"
            parent = "resources"
            required = $true
            enum = @("Windows","Mac","Linux")
            position = 1
        }
        name = @{
            description = "{0} name"
            parent = "resources"
            required = $true
            position = 2
        }
        settings = @{
            description = "An array of {0} settings"
            parent = "resources"
            type = "array"
            position = 3
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 4
        }
    }
    "requests.IoaExclusionUpdateReqV1" = @{
        id = @{
            description = "{0} identifier"
            position = 1
            required = $true
        }
        name = @{
            description = "{0} name"
            position = 2
        }
        cl_regex = @{
            description = "Command line RegEx"
            position = 3
        }
        ifn_regex = @{
            description = "Image Filename RegEx"
            position = 4
        }
        groups = @{
            dynamic = "GroupIds"
            description = "One or more Host Group identifiers, or 'all' for all Host Groups"
            type = "array"
            pattern = "(\w{32}|all)"
            position = 5
        }
        description = @{
            description = "{0} description"
            position = 6
        }
        comment = @{
            description = "Audit log comment"
            position = 7
        }
    }
    "requests.MlExclusionCreateReqV1" = @{
        value = @{
            description = "RegEx pattern value"
            position = 1
            required = $true
        }
        excluded_from = @{
            description = "Actions to exclude"
            type = "array"
            enum = @("blocking","extraction")
            position = 2
            required = $true
        }
        groups = @{
            dynamic = "GroupIds"
            description = "One or more Host Group identifiers, or 'all' for all Host Groups"
            type = "array"
            pattern = "(\w{32}|all)"
            position = 3
            required = $true
        }
        comment = @{
            description = "Audit log comment"
            position = 4
        }
    }
    "requests.RevealUninstallTokenV1" = @{
        device_id = @{
            description = "Host identifier"
            required = $true
            position = 1
        }
        audit_message = @{
            description = "Audit log comment"
            position = 2
        }
    }
    "requests.SensorUpdateSettingsV1" = @{
        build = @{}
    }
    "requests.SvExclusionCreateReqV1" = @{
        value = @{
            description = "RegEx pattern value"
            position = 1
            required = $true
        }
        groups = @{
            dynamic = "GroupIds"
            description = "One or more Host Group identifiers, or 'all' for all Host Groups"
            type = "array"
            pattern = "(\w{32}|all)"
            position = 2
            required = $true
        }
        comment = @{
            description = "Audit log comment"
            position = 3
        }
    }
    "requests.SvExclusionUpdateReqV1" = @{
        id = @{
            description = "{0} identifier"
            required = $true
            position = 1
        }
        value = @{
            description = "RegEx pattern value"
            position = 2
        }
        groups = @{
            dynamic = "GroupIds"
            description = "One or more Host Group identifiers, or 'all' for all Host Groups"
            type = "array"
            pattern = "(\w{32}|all)"
            position = 3
        }
        comment = @{
            description = "Audit log comment"
            position = 4
        }
    }
    "requests.UpdateFirewallPoliciesV1" = @{
        id = @{
            description = "{0} identifier"
            parent = "resources"
            required = $true
            position = 1
        }
        name = @{
            description = "{0} name"
            parent = "resources"
            required = $true
            position = 2
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 3
        }
    }
    "requests.UpdateGroupsV1" = @{
        id = @{
            description = "{0} identifier"
            required = $true
            parent = "resources"
            position = 1
        }
        name = @{
            description = "{0} name"
            required = $true
            parent = "resources"
            position = 2
        }
        description = @{
            description = "{0} description"
            parent = "resources"
            position = 3
        }
        assignment_rule = @{
            description = "Assignment rule for 'dynamic' {0}s"
            parent = "resources"
            position = 4
        }
    }
    "samplestore.QuerySamplesRequest" = @{
        sha256s = @{
            description = "One or more Sha256 values"
            type = "array"
            required = $true
            position = 2
            pattern = "\w{64}"
        }
    }
}