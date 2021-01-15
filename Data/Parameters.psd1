@{
    # Common parameters properties (when not defined, "in" = "body" and "type" = "string")
    action_name = @{
        description = "Action to perform"
        in = "query"
        required = $true
        position = 1
    }
    after = @{
        description = "Pagination token to retrieve the next set of results"
        in = "query"
    }
    appId = @{
        dynamic = "AppId"
        description = "Label that identifies the connection"
        in = "query"
        pattern = "\w{1,32}"
    }
    arguments = @{
        type = "string"
        description = "Arguments to include with the command"
        position = 2
    }
    base_command = @{
        dynamic = "Command"
        type = "string"
        required = $true
        description = "Real-time Response command"
        position = 1
    }
    client_id = @{
        description = "OAuth2 API client identifier"
        in = "formData"
        pattern = "\w{32}"
        position = 1
    }
    client_secret = @{
        description = "OAuth2 API client secret"
        in = "formData"
        pattern = "\w{40}"
        position = 2
    }
    clone_id = @{
        description = "Clone an existing {0}"
        pattern = "\w{32}"
        in = "query"
    }
    cloud_request_id = @{
        description = "Real-time Response Cloud Request identifier"
        in = "query"
        required = $true
        pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
    }
    comment = @{
        description = "Audit log comment"
        in = "query"
    }
    description = @{
        description = "{0} description"
    }
    fields = @{
        description = "Specific fields, or a predefined collection name surrounded by two underscores [default: __basic__]"
        type = "array"
        in = "query"
        position = 1
    }
    file = @{
        dynamic = "Path"
        type = "string"
        in = "formData"
        required = $true
        script = '[System.IO.Path]::IsPathRooted($_)'
        scripterror = "Relative paths are not permitted."
        description = "Path to local file"
        position = 2
    }
    filter = @{
        description = "Falcon Query Language expression to limit results"
        in = "query"
        position = 1
    }
    host_ids = @{
        type = "array"
        required = $true
        pattern = "\w{32}"
        description = "One or more Host identifiers"
    }
    id = @{
        description = "{0} identifier"
        in = "query"
        position = 1
    }
    ids = @{
        description = "One or more {0} identifiers"
        type = "array"
        in = "query"
        position = 1
        required = $true
    }
    include_deleted = @{
        description = "Include previously deleted {0}s"
        type = "boolean"
        in = "query"
        position = 6
    }
    limit = @{
        description = "Maximum number of results per request"
        type = "integer"
        in = "query"
        min = 1
        max = 5000
        position = 3
    }
    member_cid = @{
        description = "Child environment to use for authentication in multi-CID configurations"
        in = "formData"
        pattern = "\w{32}"
        position = 4
    }
    mode = @{
        description = "Provisioning mode [default: manual]"
        in = "query"
        enum = @("manual","cloudformation")
    }
    name = @{
        description = "{0} name"
    }
    offset = @{
        description = "Position to begin retrieving results"
        type = "integer"
        in = "query"
        position = 4
    }
    "organization-ids" = @{
        description = "One or more AWS organization identifiers"
        type = "array"
        in = "query"
        pattern = "^o-[0-9a-z]{10,32}$"
    }
    outfile_path = @{
        dynamic = "Path"
        description = "Destination path"
        in = "outfile"
        required = $true
    }
    q = @{
        description = "Perform a generic substring search across available fields"
        dynamic = "Query"
        in = "query"
        position = 2
    }
    queue_offline = @{
        type = "boolean"
        description = "Add non-responsive Hosts to the offline queue"
        position = 5
    }
    "scan-type" = @{
        description = "Scan type"
        in = "query"
        enum = @("full","dry")
        position = 2
    }
    session_id = @{
        description = "Real-time Response session identifier"
        in = "query"
        pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
        required = $true
        position = 1
    }
    sort = @{
        description = "Property and direction to sort results"
        in = "query"
        position = 2
    }
    status = @{
        description = "{0} status"
        in = "query"
        enum = @("provisioned","operational")
    }
    "tenant-id" = @{
        description = "Azure tenant identifier"
        pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
        in = "query"
        position = 2
    }
    timeout = @{
        description = "Length of time to wait for a result, in seconds"
        type = "integer"
        in = "query"
        min = 30
        max = 600
        position = 5
    }
    tracking = @{
        description = "Tracking value"
    }
    type = @{
        description = "{0} type"
        enum = @("sha256","md5","domain","ipv4","ipv6")
        in = "query"
        required = $true
        position = 1
    }
    value = @{
        description = "{0} value"
        in = "query"
        required = $true
        position = 2
    }
    "X-CS-USERUUID" = @{
        dynamic = "UserId"
        in = "query"
        required = $true
        description = "Falcon user identifier"
        pattern = "\w{8}-\w{4}-\w{4}-\w{4}-\w{12}"
        position = 1
    }
}