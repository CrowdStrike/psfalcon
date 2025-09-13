#Requires -Version 5.1
<#
.SYNOPSIS
Add or remove one or more users from the Falcon Identity Protection watchlist
.PARAMETER Username
One or more username values
.PARAMETER Add
Add username to watchlist
.PARAMETER Remote
Remove username from watchlist
.EXAMPLE
.\modify-watchlist.ps1 -Username user0, user1, user2 -Add
#>
param(
  [Parameter(ParameterSetName='Add',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
  [Parameter(ParameterSetName='Remove',Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
  [string[]]$Username,
  [Parameter(ParameterSetName='Add',Mandatory)]
  [switch]$Add,
  [Parameter(ParameterSetName='Remove',Mandatory)]
  [switch]$Remove
)
begin {
  $String = @"
mutation watchSomeUser {
  %ACTION%(input: {
    entityQuery: {
      samAccountNames: "%USERNAME%"
    }
  })
  {
    updatedEntities {
      primaryDisplayName
      secondaryDisplayName
      watched
    }
    failures {
      entityIds
      errorDetails {
        message
      }
    }
  }
}
"@
}
process {
  $Action = if ($PSCmdlet.ParameterSetName -eq 'Add') {
    # Define 'action' to take from user parameter
    'addEntitiesToWatchList'
  } else {
    'removeEntitiesFromWatchList'
  }
  foreach ($i in $Username) {
    try {
      # Make request and with defined 'Action' and 'samAccountNames'
      @(Invoke-FalconIdentityGraph -String ($String -replace '%ACTION%',$Action -replace '%USERNAME%',$i)).foreach{
        if ($_.failures) {
          # Output failures
          $_.failures
        } elseif ($_.$Action.updatedEntities) {
          # Output 'updatedEntities'
          $_.$Action.updatedEntities
        } else {
          # Output everything
          $_
        }
      }
    } catch {
      throw $_
    }
  }
}