@{
    "/samples/entities/samples/v3" = @{
        get = @{
            description = "Download a {0}"
            security = "samplestore:read"
            consumes = "*/*"
            produces = "application/octet-stream"
            parameters = @{
                "X-CS-USERUUID" = @{}
                ids = @{
                    position = 2
                }
                outfile_path = @{
                    position = 3
                }
                password_protected = @{
                    description = "Archive and set password [default: 'infected']"
                    position = 4
                    type = "boolean"
                    in = "query"
                }
            }
            responses = @{
                default = "msa.ReplyMetaOnly"
            }
        }
        post = @{
            description = "Upload a {0}"
            security = "samplestore:write"
            consumes = "application/octet-stream"
            produces = "application/json"
            parameters = @{
                "X-CS-USERUUID" = @{}
                body = @{
                    dynamic = "Path"
                    script = '[System.IO.Path]::IsPathRooted($_)'
                    scripterror = "Relative paths are not permitted."
                    description = "Path to local file"
                    pattern = "\.(acm|apk|ax|axf|bin|chm|cpl|dll|doc|docx|drv|efi|elf|eml|exe|hta|jar|js|ko|lnk|o|ocx|mod|msg|mui|pdf|pl|ppt|pps|pptx|ppsx|prx|ps1|psd1|psm1|pub|puff|py|rtf|scr|sct|so|svg|svr|swf|sys|tsp|vbe|vbs|wsf|xls|xlsx)$"
                    required = $true
                    position = 2
                }
                file_name = @{
                    description = "{0} name"
                    in = "query"
                    position = 3
                }
                is_confidential = @{
                    description = "{0} visibility in Falcon MalQuery [default: `$false]"
                    type = "boolean"
                    in = "query"
                    position = 4
                }
                comment = @{
                    position = 5
                }
            }
            responses = @{
                "samplestore.SampleMetadataResponseV2" = @(200,400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "samplestore.SampleMetadataResponseV2"
            }
        }
        delete = @{
            description = "Remove {0}s"
            security = "samplestore:write"
            consumes = "*/*"
            produces = "application/json"
            parameters = @{
                "X-CS-USERUUID" = @{}
                ids = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,403,404,500)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/samples/queries/samples/GET/v1" = @{
        post = @{
            description = "List accessible {0}s"
            security = "falconx-sandbox:write"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "samplestore.QuerySamplesRequest"
                "X-CS-USERUUID" = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200,400,403,500)
                "msa.ReplyMetaOnly" = @(429)
                default = "msa.QueryResponse"
            }
        }
    }
}