@{
    "/real-time-response/combined/batch-active-responder-command/v1" = @{
        post = @{
            description = "Issue a {0} using Active Responder privileges"
            security = "real-time-response:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.BatchExecuteCommandRequest"
                timeout = @{}
                base_command = @{
                    enum = @("cat","cd","clear","cp","csrutil","encrypt","env","eventlog","filehash","getsid",
                        "help","history","ifconfig","ipconfig","kill","ls","map","memdump","mkdir","mount","mv",
                        "netstat","ps","reg delete","reg load","reg query","reg set","reg unload","restart","rm",
                        "runscript","shutdown","umount","unmap","update history","update install","update list",
                        "update install","users","xmemdump","zip")
                }
            }
            responses = @{
                "domain.MultiCommandExecuteResponseWrapper" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/real-time-response/combined/batch-admin-command/v1" = @{
        post = @{
            description = "Issue a {0} using Admin privileges"
            security = "real-time-response-admin:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.BatchExecuteCommandRequest"
                timeout = @{}
                base_command = @{
                    enum = @("cat","cd","clear","cp","csrutil","encrypt","env","eventlog","filehash","getsid",
                        "help","history","ifconfig","ipconfig","kill","ls","map","memdump","mkdir","mount","mv",
                        "netstat","ps","put","reg delete","reg load","reg query","reg set","reg unload","restart",
                        "rm","run","runscript","shutdown","umount","unmap","update history","update install",
                        "update list","update install","users","xmemdump","zip")
                }
            }
            responses = @{
                "domain.MultiCommandExecuteResponseWrapper" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/real-time-response/combined/batch-command/v1" = @{
        post = @{
            description = "Issue a {0} using Read-Only privileges"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.BatchExecuteCommandRequest"
                timeout = @{}
                base_command = @{
                    enum = @("cat","cd","clear","csrutil","env","eventlog","filehash","getsid","help","history",
                        "ifconfig","ipconfig","ls","mount","netstat","ps","reg query","users")
                }
            }
            responses = @{
                "domain.MultiCommandExecuteResponseWrapper" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/real-time-response/combined/batch-get-command/v1" = @{
        get = @{
            description = "Retrieve the status of a batch Real-time Response 'get' command"
            security = "real-time-response:write"
            produces = "application/json"
            parameters = @{
                batch_get_cmd_req_id = @{
                    description = "Batch Real-time Response 'get' command identifier"
                    in = "query"
                    pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
                    position = 1
                    required = $true
                }
                timeout = @{
                    position = 2
                }
            }
            responses = @{
                "domain.BatchGetCmdStatusResponse" = @(200)
                "domain.APIError" = @(400,404,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
                default = "domain.BatchGetCmdStatusResponse"
            }
        }
        post = @{
            description = "Issue a batch Real-time Response 'get' command"
            security = "real-time-response:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.BatchGetCommandRequest"
                timeout = @{
                    position = 4
                }
            }
            responses = @{
                "domain.BatchGetCommandResponse" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/real-time-response/combined/batch-init-session/v1" = @{
        post = @{
            description = "Initiate a {0}"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.BatchInitSessionRequest"
                timeout = @{
                    position = 4
                }
            }
            responses = @{
                "domain.BatchInitSessionResponse" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/real-time-response/combined/batch-refresh-session/v1" = @{
        post = @{
            description = "Refresh a batch {0} to prevent expiration"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.BatchRefreshSessionRequest"
                timeout = @{
                    position = 3
                }
            }
            responses = @{
                "domain.BatchRefreshSessionResponse" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ErrorsOnly" = @(403)
                "msa.ReplyMetaOnly" = @(429)
            }
        }
    }
    "/real-time-response/entities/active-responder-command/v1" = @{
        get = @{
            description = "Check the status of a {0} request"
            security = "real-time-response:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "RtrCmdStatus"
            }
            responses = @{
                "domain.StatusResponseWrapper" = @(200)
                "domain.APIError" = @(401)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.StatusResponseWrapper"
            }
        }
        post = @{
            description = "Issue a {0} using Active Responder privileges"
            security = "real-time-response:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.CommandExecuteRequest"
                base_command = @{
                    enum = @("cat","cd","clear","cp","csrutil","encrypt","env","eventlog","filehash","get",
                        "getsid","help","history","ifconfig","ipconfig","kill","ls","map","memdump","mkdir",
                        "mount","mv","netstat","ps","reg delete","reg load","reg query","reg set","reg unload",
                        "restart","rm","runscript","shutdown","umount","unmap","update history","update install",
                        "update list","update install","users","xmemdump","zip")
                }
            }
            responses = @{
                "domain.CommandExecuteResponseWrapper" = @(201)
                "domain.APIError" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/real-time-response/entities/admin-command/v1" = @{
        get = @{
            description = "Check the status of a {0} request"
            security = "real-time-response-admin:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "RtrCmdStatus"
            }
            responses = @{
                "domain.StatusResponseWrapper" = @(200)
                "domain.APIError" = @(401)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.StatusResponseWrapper"
            }
        }
        post = @{
            description = "Issue a {0} using Admin privileges"
            security = "real-time-response-admin:write"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.CommandExecuteRequest"
                base_command = @{
                    enum = @("cat","cd","clear","cp","csrutil","encrypt","env","eventlog","filehash","get",
                        "getsid","help","history","ifconfig","ipconfig","kill","ls","map","memdump","mkdir",
                        "mount","mv","netstat","ps","put","reg delete","reg load","reg query","reg set",
                        "reg unload","restart","rm","run","runscript","shutdown","umount","unmap",
                        "update history","update install","update list","update install","users","xmemdump","zip")
                }
            }
            responses = @{
                "domain.CommandExecuteResponseWrapper" = @(201)
                "domain.APIError" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/real-time-response/entities/command/v1" = @{
        get = @{
            description = "Check the status of a {0} request"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "RtrCmdStatus"
            }
            responses = @{
                "domain.StatusResponseWrapper" = @(200)
                "domain.APIError" = @(401)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.StatusResponseWrapper"
            }
        }
        post = @{
            description = "Issue a {0} using Read-Only privileges"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.CommandExecuteRequest"
                base_command = @{
                    enum = @("cat","cd","clear","csrutil","env","eventlog","filehash","getsid","help","history",
                        "ifconfig","ipconfig","ls","mount","netstat","ps","reg query","users")
                }
            }
            responses = @{
                "domain.CommandExecuteResponseWrapper" = @(201)
                "domain.APIError" = @(400)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/real-time-response/entities/extracted-file-contents/v1" = @{
        get = @{
            description = "Download a {0}"
            security = "real-time-response:write"
            produces = "application/x-7z-compressed"
            parameters = @{
                sha256 = @{
                    description = "Sha256 hash value of file to download"
                    in = "query"
                    required = $true
                    position = 1
                }
                session_id = @{
                    position = 2
                }
                outfile_path = @{
                    position = 3
                    pattern = "^*\.7z$"
                }
            }
            responses = @{
                "domain.APIError" = @(400,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/real-time-response/entities/file/v1" = @{
        get = @{
            description = "Check the status of a Real-time Response 'get' command request"
            security = "real-time-response:write"
            produces = "application/json"
            parameters = @{
                session_id = @{}
            }
            responses = @{
                "domain.ListFilesResponseWrapper" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.ListFilesResponseWrapper"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "real-time-response:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
                session_id = @{
                    position = 2
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(204,403,429)
                "domain.APIError" = @(400,404)
            }
        }
    }
    "/real-time-response/entities/put-files/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "real-time-response-admin:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "binservclient.MsaPFResponse" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "binservclient.MsaPFResponse"
            }
        }
        post = @{
            description = "Upload a {0}"
            security = "real-time-response-admin:write"
            consumes = "multipart/form-data"
            produces = "application/json"
            parameters = @{
                file = @{
                    position = 1
                }
                name = @{
                    description = "{0} name"
                    in = "formData"
                    position = 2
                }
                description = @{
                    description = "{0} description"
                    in = "formData"
                    position = 3
                }
                comments_for_audit_log = @{
                    dynamic = "Comment"
                    description = "Audit log comment"
                    max = 4096
                    in = "formData"
                    position = 4
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,403,429)
                "domain.APIError" = @(400)
                default = "msa.ReplyMetaOnly"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "real-time-response-admin:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,404,429)
                default = "msa.ReplyMetaOnly"
            }
        }
    }
    "/real-time-response/entities/queued-sessions/GET/v1" = @{
        post = @{
            description = "Retrieve detailed queued Real-time Response session information"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "msa.IdsRequest"
                queue_switch = @{
                    dynamic = "Queue"
                    type = "switch"
                    description = "Restrict search to queued sessions"
                    required = $true
                }
            }
            responses = @{
                "domain.QueuedSessionResponseWrapper" = @(200)
                "domain.APIError" = @(400,401,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.QueuedSessionResponseWrapper"
            }
        }
    }
    "/real-time-response/entities/queued-sessions/command/v1" = @{
        delete = @{
            description = "Remove a queued Real-time Response command"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "RtrCmdStatus"
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(204,403,429)
                "domain.APIError" = @(400,401)
            }
        }
    }
    "/real-time-response/entities/refresh-session/v1" = @{
        post = @{
            description = "Refresh a {0} to prevent expiration"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.InitRequest"
            }
            responses = @{
                "domain.InitResponseWrapper" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/real-time-response/entities/scripts/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "real-time-response-admin:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "binservclient.MsaPFResponse" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "binservclient.MsaPFResponse"
            }
        }
        post = @{
            description = "Upload a {0}"
            security = "real-time-response-admin:write"
            consumes = "multipart/form-data"
            produces = "application/json"
            parameters = @{
                file = @{
                    position = 1
                }
                platform = @{
                    description = "Operating System platform"
                    enum = @("windows","mac","linux")
                    type = "string"
                    in = "formData"
                    required = $true
                    position = 2
                }
                permission_type = @{
                    in = "formData"
                    required = $true
                    enum = @("private","group","public")
                    description = "{0} permission level"
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
            responses = @{
                "msa.ReplyMetaOnly" = @(200,403,429)
                "domain.APIError" = @(400)
                default = "msa.ReplyMetaOnly"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "real-time-response-admin:write"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,400,403,404,429)
                default = "msa.ReplyMetaOnly"
            }
        }
        patch = @{
            description = "Modify {0}s"
            security = "real-time-response-admin:write"
            consumes = "multipart/form-data"
            produces = "application/json"
            parameters = @{
                id = @{
                    description = "{0} identifier"
                    in = "formData"
                    required = $true
                    position = 1
                }
                file = @{}
                platform = @{
                    description = "Operating System platform"
                    enum = @("windows","mac","linux")
                    type = "string"
                    in = "formData"
                    position = 3
                }
                permission_type = @{
                    in = "formData"
                    enum = @("private","group","public")
                    description = "{0} permission level"
                    position = 4
                }
                name = @{
                    description = "{0} name"
                    in = "formData"
                    position = 5
                }
                description = @{
                    description = "{0} description"
                    in = "formData"
                    position = 6
                }
                comments_for_audit_log = @{
                    dynamic = "Comment"
                    description = "Audit log comment"
                    max = 4096
                    in = "formData"
                    position = 7
                }
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(200,403,429)
                "domain.APIError" = @(400)
                default = "msa.ReplyMetaOnly"
            }
        }
    }
    "/real-time-response/entities/sessions/GET/v1" = @{
        post = @{
            description = "Retrieve detailed {0} information"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "msa.IdsRequest"
            }
            responses = @{
                "domain.SessionResponseWrapper" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.SessionResponseWrapper"
            }
        }
    }
    "/real-time-response/entities/sessions/v1" = @{
        post = @{
            description = "Initiate a {0}"
            security = "real-time-response:read"
            produces = "application/json"
            consumes = "application/json"
            parameters = @{
                schema = "domain.InitRequest"
            }
            responses = @{
                "domain.InitResponseWrapper" = @(201)
                "domain.APIError" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "real-time-response:read"
            produces = "application/json"
            parameters = @{
                session_id = @{}
            }
            responses = @{
                "msa.ReplyMetaOnly" = @(204,403,429)
                "domain.APIError" = @(400,401)
            }
        }
    }
    "/real-time-response/queries/put-files/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "real-time-response-admin:write"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 100
                }
            }
            responses = @{
                "binservclient.MsaPutFileResponse" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "binservclient.MsaPutFileResponse"
            }
        }
    }
    "/real-time-response/queries/scripts/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "real-time-response-admin:write"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 100
                }
            }
            responses = @{
                "binservclient.MsaPutFileResponse" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "binservclient.MsaPutFileResponse"
            }
        }
    }
    "/real-time-response/queries/sessions/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "real-time-response:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParams"
                limit = @{
                    max = 100
                }
            }
            responses = @{
                "domain.ListSessionsResponseMsa" = @(200)
                "domain.APIError" = @(400,404)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.ListSessionsResponseMsa"
            }
        }
    }
}