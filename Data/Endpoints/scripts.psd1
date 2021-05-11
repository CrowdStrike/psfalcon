@{
    script = @{
        CreateGroupArray = @{
            description = "Create multiple groups in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of groups to create"
                    required = $true
                }
            }
        }
        EditGroupArray = @{
            description = "Modify multiple groups in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of groups to modify"
                    required = $true
                }
            }
        }
        CreateIOCArray = @{
            description = "Create multiple Custom Indicators in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of Custom Indicators to create"
                    required = $true
                    position = 1
                }
                comment = @{
                    description = "Audit log comment"
                    in = "body"
                    position = 2
                }
                retrodetects = @{
                    dynamic = "RetroDetects"
                    in = "query"
                    type = "boolean"
                    description = "Generate retroactive detections for hosts that have observed the Custom Indicators"
                    position = 3
                }
                ignore_warnings = @{
                    in = "query"
                    type = "boolean"
                    description = "Ignore warnings and modify all Custom Indicators"
                    position = 4
                }
            }
        }
        EditIOCArray = @{
            description = "Modify multiple Custom Indicators in a single request"
            parameters = @{
                filter = @{
                    description = "Falcon Query Language expression to find and delete Custom Indicators"
                    parent = "bulk_update"
                    required = $true
                    in = "body"
                    position = 1
                }
                action = @{
                    description = "Action to take when a host observes the Custom Indicator"
                    parent = "bulk_update"
                    enum = @("no_action","allow","prevent_no_ui","detect","prevent")
                    position = 2
                }
                platforms = @{
                    description = "Platform that the Custom Indicator applies to"
                    parent = "bulk_update"
                    type = "array"
                    enum = @("linux","mac","windows")
                    position = 3
                }
                source = @{
                    description = "The source where this Custom Indicator originated"
                    parent = "bulk_update"
                    min = 1
                    max = 256
                    position = 4
                }
                severity = @{
                    description = "Severity level to apply to the Custom Indicator"
                    parent = "bulk_update"
                    enum = @("informational","low","medium","high","critical")
                    position = 5
                }
                description = @{
                    description = "Descriptive label for the Custom Indicator"
                    parent = "bulk_update"
                    position = 6
                }
                tags = @{
                    description = "List of tags to apply to the Custom Indicator"
                    parent = "bulk_update"
                    type = "array"
                    position = 7
                }
                host_groups = @{
                    description = "One or more Host Group identifiers to assign the Custom Indicator"
                    parent = "bulk_update"
                    type = "array"
                    pattern = "\w{32}"
                    position = 8
                }
                applied_globally = @{
                    description = "Globally assign the Custom Indicator instead of assigning to specific Host Groups"
                    parent = "bulk_update"
                    type = "boolean"
                    position = 9
                }
                expiration = @{
                    description = "The date on which the Custom Indicator will become inactive. When a Custom Indicator expires, its action is set to 'no_action' but it remains in your list of Custom Indicators."
                    parent = "bulk_update"
                    position = 10
                }
                comment = @{
                    in = "body"
                    position = 11
                }
                retrodetects = @{
                    dynamic = "RetroDetects"
                    in = "query"
                    type = "boolean"
                    description = "Generate retroactive detections for hosts that have observed the Custom Indicators"
                    position = 12
                }
                ignore_warnings = @{
                    in = "query"
                    type = "boolean"
                    description = "Ignore warnings and modify all Custom Indicators"
                    position = 13
                }
            }
        }
        CreatePolicyArray = @{
            description = "Create multiple policies in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of policies to create"
                    required = $true
                }
            }
        }
        EditPolicyArray = @{
            description = "Modify multiple policies in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of policies to modify"
                    required = $true
                }
            }
        }
        CreateReconRuleArray = @{
            description = "Create multiple Falcon X Recon monitoring rules in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of rules to create"
                    required = $true
                }
            }
        }
        EditReconRuleArray = @{
            description = "Modify multiple Falcon X Recon monitoring rules in a single request"
            parameters = @{
                array = @{
                    type = "array"
                    description = "An array of rules to modify"
                    required = $true
                }
            }
        }
        ExportReport = @{
            description = "Format a response object and output to CSV"
            parameters = @{
                path = @{
                    type = "string"
                    description = "Output path and file name"
                    position = 1
                    required = $true
                    pattern = "\.csv$"
                }
                object = @{
                    type = "object"
                    description = "A result object to format (can be passed via pipeline)"
                    position = 2
                    required = $true
                    pipeline = $true
                }
            }
        }
        FindDuplicate = @{
            description = "Lists potential duplicates from detailed 'Host' results"
            parameters = @{
                hosts = @{
                    type = "array"
                    description = "Array of detailed 'Host' results"
                    position = 1
                    required = $true
                }
            }
        }
        GetQueue = @{
            description = "Create a report of with status of queued Real-time Response sessions"
            security = "real-time-response:read, real-time-response:write, real-time-response-admin:write"
            parameters = @{
                days = @{
                    type = "int"
                    description = "Number of days worth of results to retrieve [default: 7]"
                    position = 1
                }
            }
        }
        InvokeDeploy = @{
            description = "Deploy and run an executable using Real-time Response"
            security = "real-time-response:read, real-time-response-admin:write"
            parameters = @{
                host_ids = @{
                    position = 1
                }
                path = @{
                    type = "string"
                    required = $true
                    description = "Path to local file"
                    position = 2
                }
                arguments = @{
                    description = "Arguments to include when running the executable"
                    position = 3
                }
                timeout = @{
                    position = 4
                }
                queue_offline = @{}
            }
        }
        InvokeRTR = @{
            security = "real-time-response:read, real-time-response:write"
            description = "Start a session execute a Real-time Response command and output results"
            parameters = @{
                base_command = @{
                    enum = @("cat","cd","clear","cp","csrutil","encrypt","env","eventlog","filehash","get",
                        "getsid","history","ifconfig","ipconfig","kill","ls","map","memdump","mkdir","mount",
                        "mv","netstat","ps","put","reg query","reg set","reg delete","reg load","reg unload",
                        "restart","rm","run","runscript","shutdown","umount","update list","update history",
                        "update install","update query","unmap","users","xmemdump","zip")
                }
                arguments = @{}
                host_ids = @{
                    position = 3
                }
                timeout = @{
                    position = 4
                }
                queue_offline = @{}
            }
        }
        MalQueryHash = @{
            description = "Perform a simple MalQuery YARA search for a specific hash"
            security = "malquery:write"
            parameters = @{
                sha256 = @{
                    description = "SHA256 hash value"
                    type = "string"
                    pattern = "\w{64}"
                    required = $true
                    position = 1
                }
            }
        }
        OpenStream = @{
            description = "Export recent Event Stream data to a Json file in your current directory"
            security = "streaming:read"
        }
        QuickScanQuota = @{
            description = "Display your Falcon QuickScan quota information"
            method = "get"
            path = "/scanner/queries/scans/v1"
        }
        ShowMap = @{
            path = "/intelligence/graph?indicators="
            method = "post"
            description = "Use your default browser to show indicators on the Indicator Map"
            parameters = @{
                indicators = @{
                    description = "Indicators to graph"
                    type = "array"
                    in = "query"
                    required = $true
                    pattern = "(sha256|md5|domain|ipv4|ipv6):.*"
                }
            }
        }
        ShowModule = @{
            description = "Output PSFalcon diagnostic information"
        }
        SubmissionQuota = @{
            path = "/falconx/queries/submissions/v1"
            method = "get"
            description = "Display your Falcon X submission quota information"
        }
        TestToken = @{
            description = "Display OAuth2 client and access token information"
        }
    }
}