@{
  Name = "scripts/InvokeDeploy"
  Description = "Deploy and run an executable using Real-time Response"
  Permission = "real-time-response:read real-time-response-admin:write"
  Parameters = @(
    @{
      Dynamic = "HostIds"
      Type = "array"
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more Host identifiers"
      Position = 1
    }
    @{
      Dynamic = "Path"
      Type = "string"
      Required = $true
      Script = '[System.IO.Path]::IsPathRooted($_)'
      ScriptError = "Relative paths are not permitted."
      Description = "Path to the executable"
      Position = 2
    }
    @{
      Dynamic = "Arguments"
      Type = "string"
      Required = $false
      Description = "Command line arguments to include upon execution"
      Position = 3
    }
    @{
      Dynamic = "Timeout"
      Type = "int"
      Required = $false
      Min = 30
      Max = 600
      Description = "Length of time to wait for a result in seconds"
      Position = 4
    }
    @{
      Dynamic = "QueueOffline"
      Type = "bool"
      Required = $false
      Description = "Add session to the offline queue if the host does not initialize"
      Position = 5
    }
  )
}