@{
  Name = "scripts/InvokeRTR"
  Permission = "real-time-response:read real-time-response:write"
  Description = "Start a session execute a Real-time Response command and output results"
  Parameters = @(
    @{
      Dynamic = "Command"
      Type = "string"
      Required = $true
      Enum = @(
        "cat"
        "cd"
        "clear"
        "cp"
        "csrutil"
        "encrypt"
        "env"
        "eventlog"
        "filehash"
        "get"
        "getsid"
        "help"
        "history"
        "ifconfig"
        "ipconfig"
        "kill"
        "ls"
        "map"
        "memdump"
        "mkdir"
        "mount"
        "mv"
        "netstat"
        "ps"
        "put"
        "reg query"
        "reg set"
        "reg delete"
        "reg load"
        "reg unload"
        "restart"
        "rm"
        "run"
        "runscript"
        "shutdown"
        "umount"
        "unmap"
        "users"
        "xmemdump"
        "zip"
      )
      Description = "Command to execute"
      Position = 1
    }
    @{
      Dynamic = "HostIds"
      Type = "array"
      Required = $true
      Pattern = "\w{32}"
      Description = "One or more host identifiers"
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
      Description = "Add sessions in this batch to the offline queue if the hosts do not initialize"
      Position = 5
    }
  )
}