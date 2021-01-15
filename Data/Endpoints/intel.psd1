@{
    "/intel/combined/actors/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "falconx-actors:read"
            produces = "application/json"
            parameters = @{
                fields = @{}
                filter = @{
                    position = 2
                }
                q = @{
                    position = 3
                }
                sort = @{
                    position = 4
                }
                limit = @{
                    position = 5
                }
                offset = @{
                    position = 6
                }
            }
            responses = @{
                "domain.ActorsResponse" = @(200)
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.ActorsResponse"
            }
        }
    }
    "/intel/combined/indicators/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "falconx-indicators:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                include_deleted = @{}
            }
            responses = @{
                "domain.PublicIndicatorsV3Response" = @(200)
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "domain.PublicIndicatorsV3Response"
            }
        }
    }
    "/intel/combined/reports/v1" = @{
        get = @{
            description = "Search for detailed information about {0}s"
            security = "falconx-reports:read"
            produces = "application/json"
            parameters = @{
                fields = @{}
                filter = @{
                    position = 2
                }
                q = @{
                    position = 3
                }
                sort = @{
                    position = 4
                }
                limit = @{
                    position = 5
                }
                offset = @{
                    position = 6
                }
            }
            responses = @{
                "domain.NewsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                "msa.ErrorsOnly" = @(500)
                default = "domain.NewsResponse"
            }
        }
    }
    "/intel/entities/actors/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "falconx-actors:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
                fields = @{
                    position = 2
                }
            }
            responses = @{
                "domain.ActorsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                "msa.ErrorsOnly" = @(500)
                default = "domain.ActorsResponse"
            }
        }
    }
    "/intel/entities/indicators/GET/v1" = @{
        post = @{
            description = "Retrieve detailed {0} information"
            security = "falconx-indicators:read"
            consumes = "application/json"
            produces = "application/json"
            parameters = @{
                schema = "msa.IdsRequest"
            }
            responses = @{
                "domain.PublicIndicatorsV3Response" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                "msa.ErrorsOnly" = @(500)
                default = "domain.PublicIndicatorsV3Response"
            }
        }
    }
    "/intel/entities/report-files/v1" = @{
        get = @{
            description = "Download an {0}"
            security = "falconx-reports:read"
            produces = "application/pdf"
            parameters = @{
                id = @{
                    required = $true
                }
                outfile_path = @{
                    pattern = "\.pdf$"
                    position = 2
                }
            }
            responses = @{
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/intel/entities/reports/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "falconx-reports:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
                fields = @{
                    position = 2
                }
            }
            responses = @{
                "domain.NewsResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                "msa.ErrorsOnly" = @(500)
                default = "domain.NewsResponse"
            }
        }
    }
    "/intel/entities/rules-files/v1" = @{
        get = @{
            description = "Download a {0}"
            security = "falconx-rules:read"
            produces = "application/zip"
            parameters = @{
                id = @{
                    required = $true
                }
                outfile_path = @{
                    pattern = "\.(gzip|zip)$"
                    position = 2
                }
            }
            responses = @{
                "msa.ErrorsOnly" = @(400,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/intel/entities/rules-latest-files/v1" = @{
        get = @{
            description = "Download the latest {0}"
            security = "falconx-rules:read"
            produces = "application/zip"
            parameters = @{
                type = @{
                    enum = @("snort-suricata-master","snort-suricata-update",
                        "snort-suricata-changelog","yara-master","yara-update",
                        "yara-changelog","common-event-format","netwitness")
                }
                outfile_path = @{
                    pattern = "\.(gzip|zip)$"
                    position = 2
                }
            }
            responses = @{
                "msa.ErrorsOnly" = @(400,404,500)
                "msa.ReplyMetaOnly" = @(403,429)
            }
        }
    }
    "/intel/entities/rules/v1" = @{
        get = @{
            description = "Retrieve detailed {0} information"
            security = "falconx-rules:read"
            produces = "application/json"
            parameters = @{
                ids = @{}
            }
            responses = @{
                "domain.RulesResponse" = @(200)
                "msa.ReplyMetaOnly" = @(403,429)
                "msa.ErrorsOnly" = @(500)
                default = "domain.RulesResponse"
            }
        }
    }
    "/intel/queries/actors/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "falconx-actors:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/intel/queries/indicators/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "falconx-indicators:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
                include_deleted = @{}
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/intel/queries/reports/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "falconx-reports:read"
            produces = "application/json"
            parameters = @{
                schema = "BasicParamsQuery"
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
    "/intel/queries/rules/v1" = @{
        get = @{
            description = "Search for {0}s"
            security = "falconx-rules:read"
            produces = "application/json"
            parameters = @{
                type = @{
                    enum = @("snort-suricata-master","snort-suricata-update",
                        "snort-suricata-changelog","yara-master","yara-update",
                        "yara-changelog","common-event-format","netwitness")
                    position = 1
                }
                name = @{
                    type = "array"
                    in = "query"
                    position = 2
                }
                description = @{
                    type = "array"
                    in = "query"
                    position = 3
                }
                tags = @{
                    description = "{0} tags"
                    type = "array"
                    in = "query"
                    position = 4
                }
                min_created_date = @{
                    description = "Filter results to those created on or after a date"
                    type = "integer"
                    in = "query"
                    position = 5
                }
                max_created_date = @{
                    description = "Filter results to those created on or before a date"
                    in = "query"
                    position = 6
                }
                q = @{
                    position = 7
                }
                sort = @{
                    position = 8
                }
                limit = @{
                    position = 9
                }
                offset = @{
                    position = 10
                }
            }
            responses = @{
                "msa.QueryResponse" = @(200)
                "msa.ErrorsOnly" = @(400,500)
                "msa.ReplyMetaOnly" = @(403,429)
                default = "msa.QueryResponse"
            }
        }
    }
}