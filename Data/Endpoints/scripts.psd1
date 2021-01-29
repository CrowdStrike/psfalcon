@{
    script = @{
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
        SubmissionQuota = @{
            path = "/falconx/queries/submissions/v1"
            method = "get"
            description = "Display your Falcon X submission quota information"
        }
    }
}