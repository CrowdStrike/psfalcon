function Add-Include {
  [CmdletBinding()]
  [OutputType([void])]
  param([object[]]$Object,[object]$UserInput,[hashtable]$Index,[string]$Command)
  if ($UserInput.Include) {
    if (!$Object.id -and $Object -isnot [PSCustomObject]) {
      # Create array of [PSCustomObject] with 'id' property
      $Object = @($Object).foreach{ ,[PSCustomObject]@{ id = $_ }}
    } else {
      $Detailed = $true
    }
    if ($Index) {
      $Index.GetEnumerator().foreach{
        # Use 'Index' for 'Include' name and command to gather value(s) and append to output
        if ($UserInput.Include -contains $_.Key) {
          if ($_.Key -eq 'members') {
            foreach ($i in $Object) {
              # Add 'members' by object
              $SetParam = @{
                Object = $i
                Name = $_.Key
                Value = if ($_.Value -eq 'Get-FalconHostGroupMember') {
                  if ($Detailed -eq $true) {
                    try { Get-FalconHost -Filter "groups:['$($i.id)']" -Detailed -All } catch { Write-Error $_ }
                  } else {
                    try { Get-FalconHost -Filter "groups:['$($i.id)']" -All } catch { Write-Error $_ }
                  }
                } else {
                  if ($Detailed -eq $true) {
                    try { & "$($_.Value)" -Id $i.id -Detailed -All } catch { Write-Error $_ }
                  } else {
                    try { & "$($_.Value)" -Id $i.id -All } catch { Write-Error $_ }
                  }
                }
              }
              Set-Property @SetParam
            }
          } else {
            $Output = try { & "$($_.Value)" -Id $Object.id } catch { Write-Error $_ }
            foreach ($i in $Output) {
              $SetParam = @{
                Object = if ($i.policy_id) {
                  @($Object).Where({$_.id -eq $i.policy_id})
                } else {
                  @($Object).Where({$_.id -eq $i.id})
                }
                Name = $_.Key
                Value = $i
              }
              Set-Property @SetParam
            }
          }
        }
      }
    } elseif ($Command) {
      $Output = try { & $Command -Id $Object.id } catch { Write-Error $_ }
      foreach ($i in $Output) {
        @($UserInput.Include).foreach{
          # Append all properties from 'Include'
          $SetParam = @{
            Object = if ($i.device_id) {
              @($Object).Where({$_.id -eq $i.device_id})
            } else {
              @($Object).Where({$_.id -eq $i.id})
            }
            Name = $_
            Value = $i.$_
          }
          Set-Property @SetParam
        }
      }
    }
  }
  return $Object
}
function Assert-Extension {
  [CmdletBinding()]
  [OutputType([string])]
  param([string]$Path,[string]$Extension)
  process {
    # Verify that 'Path' has a file extension matching 'Extension'
    if ($Path -and $Extension) {
      if ([System.IO.Path]::GetExtension($Path) -eq ".$Extension") {
        $Path
      } else {
        $Path,$Extension -join '.'
      }
    }
  }
}
function Build-Content {
  [CmdletBinding()]
  [OutputType([hashtable])]
  param([hashtable]$Format,[object]$UserInput)
  begin {
    function Build-Body ($Format,$UserInput) {
      $Body = @{}
      $UserInput.GetEnumerator().Where({$Format.Body.Values -match $_.Key}).foreach{
        if ($_.Key -eq 'raw_array') {
          $RawArray = @($_.Value)
        } else {
          $Field = ($_.Key).ToLower()
          $Value = if ($_.Value -is [string] -and $_.Value -eq 'null') {
            # Convert [string] values of 'null' to null values
            $null
          } elseif ($_.Value -is [array]) {
            # Convert [string] values of 'null' to null values
            ,($_.Value).foreach{ if ($_ -is [string] -and $_ -eq 'null') { $null } else { $_ } }
          } else {
            $_.Value
          }
          if ($Field -eq 'body' -and ($Format.Body.root | Measure-Object).Count -eq 1) {
            # Add 'body' value as [System.Net.Http.ByteArrayContent] when it's the only property
            $FullFilePath = $Script:Falcon.Api.Path($_.Value)
            $ByteStream = if ($PSVersionTable.PSVersion.Major -ge 6) {
              Get-Content $FullFilePath -AsByteStream
            } else {
              Get-Content $FullFilePath -Encoding Byte -Raw
            }
            $ByteArray = [System.Net.Http.ByteArrayContent]::New($ByteStream)
            $ByteArray.Headers.Add('Content-Type',$Headers.ContentType)
          } else {
            if (!$Body) { $Body = @{} }
            if (($Value -is [array] -or $Value -is [string]) -and ($Value |
            Get-Member -MemberType Method).Where({$_.Name -eq 'Normalize'})) {
              # Normalize values to avoid Json conversion errors when 'Get-Content' was used
              if ($Value -is [array]) {
                $Value = [array]($Value).Normalize()
              } elseif ($Value -is [string]) {
                $Value = ($Value).Normalize()
              }
            }
            $Format.Body.GetEnumerator().Where({$_.Value -eq $Field}).foreach{
              if ($_.Key -eq 'root') {
                # Add key/value pair directly to 'Body'
                $Body.Add($Field,$Value)
              } else {
                # Create parent object and add key/value pair
                if (!$Parents) { $Parents = @{} }
                if (!$Parents.($_.Key)) { $Parents[$_.Key] = @{} }
                $Parents.($_.Key).Add($Field,$Value)
              }
            }
          }
        }
      }
      if ($ByteArray) {
        # Return 'ByteArray' object
        $ByteArray
      } elseif ($RawArray) {
        # Return 'RawArray' object and force [array]
        ,$RawArray
      } else {
        # Add parents as arrays in 'Body' and return 'Body' object
        if ($Parents) { $Parents.GetEnumerator().foreach{ $Body[$_.Key] = @($_.Value) }}
        if (($Body.Keys | Measure-Object).Count -gt 0) { $Body }
      }
    }
    function Build-Formdata ($Format,$UserInput) {
      $Formdata = @{}
      $UserInput.GetEnumerator().Where({$Format.Formdata -contains $_.Key}).foreach{
        $Formdata[($_.Key).ToLower()] = if ($_.Key -eq 'content') {
          $Content = try {
            # Collect file content as a string
            [string](Get-Content ($Script:Falcon.Api.Path($_.Value)) -Raw -EA 0)
          } catch {
            $null
          }
          # Supply original value if no file content is gathered
          if ($Content) { $Content } else { $_.Value }
        } else {
          $_.Value
        }
      }
      # Return 'Formdata' object
      if (($Formdata.Keys | Measure-Object).Count -gt 0) { $Formdata }
    }
    function Build-Query ($Format,$UserInput) {
      # Regex pattern for matching 'last [int] days/hours'
      [regex]$Relative = '([Ll]ast (?<Int>\d{1,}) ([Dd]ay[s]?|[Hh]our[s]?))'
      [string[]]$Query = foreach ($Field in $Format.Query.Where({$UserInput.Keys -contains $_})) {
        foreach ($Value in ($UserInput.GetEnumerator().Where({$_.Key -eq $Field}).Value)) {
          if ($Field -eq 'filter' -and $Value -match $Relative) {
            # Convert 'last [int] days/hours' to Rfc3339
            @($Value | Select-String $Relative -AllMatches).foreach{
              foreach ($Match in $_.Matches.Value) {
                [int]$Int = $Match -replace $Relative,'${Int}'
                $Int = if ($Match -match 'day') { $Int * -24 } else { $Int * -1 }
                $Value = $Value -replace $Match,(Convert-Rfc3339 $Int)
              }
            }
          }
          # Output array of [string] with URL-encoded values to append to 'Path'
          ,($Field,([System.Uri]::EscapeDataString($Value)) -join '=')
        }
      }
      # Return 'Query'
      if ($Query) { $Query }
    }
  }
  process {
    if ($Format) {
      [System.Collections.Generic.List[string]]$Expected = @()
      @($Format.Values).foreach{
        # Determine expected field values using 'Format'
        if ($_.Keys) {
          @($_.Values).foreach{ @($_).foreach{ $Expected.Add($_) }}
        } else {
          @($_).foreach{ $Expected.Add($_) }
        }
      }
      if ($Expected) {
        @($UserInput.Keys).foreach{
          if ($Expected -notcontains $_ -and (Get-Command $Command).Parameters.Keys -contains $_) {
            # Create duplicate parameter using 'Alias' and remove original when expected
            $Alias = ((Get-Command $Command).Parameters.$_.Aliases)[0]
            if ($Alias -and $Expected -contains $Alias) {
              $UserInput[$Alias] = $UserInput.$_
              [void]$UserInput.Remove($_)
            }
          }
        }
      }
    }
    if ($UserInput) {
      $Content = @{}
      @('Body','Formdata','Outfile','Query').foreach{
        if ($Format.$_) {
          $Value = if ($_ -eq 'Outfile') {
            # Get absolute path for 'OutFile'
            $Outfile = $UserInput.GetEnumerator().Where({$Format.Outfile -eq $_.Key}).Value
            if ($Outfile) { $Script:Falcon.Api.Path($Outfile) }
          } else {
            # Get value(s) from each 'Build' function
            & "Build-$_" -Format $Format -UserInput $UserInput
          }
          if ($Value) { $Content[$_] = $Value }
        }
      }
    }
  }
  end {
     # Return 'Content' table
    if (($Content.Keys | Measure-Object).Count -gt 0) { $Content }
  }
}
function Confirm-CidValue ([string]$String) {
  if ($String -match '^[a-fA-F0-9]{32}-\w{2}$') {
    # If input matches CID with checksum, strip checksum
    ($String.Split('-')[0]).ToLower()
  } elseif ($String -match '^[a-fA-F0-9]{32}$') {
    # If input matches CID, return CID
    $String.ToLower()
  } else {
    throw "'$String' is not a valid customer identifier value."
  }
}
function Confirm-Parameter {
  [CmdletBinding()]
  [OutputType([boolean])]
  param(
    [Parameter(Mandatory,Position=1)]
    [object[]]$Object,
    [Parameter(Mandatory,Position=2)]
    [string]$Command,
    [Parameter(Mandatory,Position=3)]
    [string]$Endpoint
  )
  begin {
    function Get-ParameterName ([System.Management.Automation.ParameterMetadata]$Parameter) {
      # Return parameter name, or first alias when present
      if ($Parameter.Aliases) { $Parameter.Aliases[0] } else { $Parameter.Name }
    }
  }
  process {
    foreach ($i in $Object) {
      # Retrieve parameters from target $Endpoint and create object string for error message
      [System.Management.Automation.ParameterMetadata[]]$PmList = @(
        (Get-Command $Command).Parameters.Values).Where({$_.ParameterSets.Keys -contains $Endpoint})
      [string]$ErrorObject = ConvertTo-Json $i -Depth 32 -Compress
      [string[]]$Keys = if ($i -is [hashtable]) {
        $i.Keys
      } elseif ($i -is [PSCustomObject]) {
        $i.PSObject.Members.Where({$_.MemberType -eq 'NoteProperty'}).Name
      } else {
        throw "Use [hashtable] or [PSCustomObject]."
      }
      if ($Keys) {
        @($PmList.Where({$_.attributes.Mandatory -eq $true}).foreach{ Get-ParameterName $_ }).foreach{
          # Verify object contains required properties
          if ($Keys -notcontains $_) { throw "Missing required property '$_'. $ErrorObject" } else { $true }
        }
        foreach ($Name in $Keys) {
          # Gather parameter detail for each property in object
          $Parameter = $PmList.Where({$_.Name -eq $Name -or ($_.Aliases -and @($_.Aliases)[0] -eq $Name )})
          if ($Parameter) {
            if ($Parameter.Aliases -and @($Parameter.Aliases)[0] -cne $Name) {
              # Error if property is not accurately named for submission
              throw "Unexpected property '$Name'. Try '$(@($Parameter.Aliases)[0])'. $ErrorObject"
            } else {
              $true
            }
            # Collect 'ValidateSet' values
            [string[]]$ValidSet = $Parameter.Attributes.ValidValues
            if ($ValidSet) {
              if ($i.$Name -and $i.$Name -is [array]) {
                foreach ($Value in $i.$Name) {
                  # Error if array value is not in 'ValidateSet'
                  if ($ValidSet -cnotcontains $Value) {
                    throw "'$Value' is not a valid '$Name' value. $ErrorObject"
                  } else {
                    $true
                  }
                }
              } elseif ($i.$Name -and $ValidSet -cnotcontains $i.$Name) {
                # Error if value is not in 'ValidateSet'
                throw "'$($i.$Name)' is not a valid '$Name' value. $ErrorObject"
              } else {
                $true
              }
            }
            # Collect 'ValidatePattern' value
            [string]$ValidPattern = $Parameter.attributes.RegexPattern
            if ($ValidPattern) {
              if ($i.$Name -and $i.$Name -is [array]) {
                foreach ($Value in $i.$Name) {
                  # Error if array value does not match 'ValidatePattern'
                  if ($Value -notmatch $ValidPattern) {
                    throw "'$Value' is not a valid '$Name' value. $ErrorObject"
                  } else {
                    $true
                  }
                }
                $true
              } elseif ($i.$Name -and $i.$Name -notmatch $ValidPattern) {
                # Error if value does not match 'ValidatePattern'
                throw "'$($i.$Name)' is not a valid '$Name' value. $ErrorObject"
              } else {
                $true
              }
            }
          }
        }
      }
    }
  }
}
function Convert-Rfc3339 {
  [CmdletBinding()]
  [OutputType([string])]
  param([int32]$Hours)
  process {
    # Return Rfc3339 timestamp for $Hours from Get-Date
    "$([Xml.XmlConvert]::ToString(
      (Get-Date).AddHours($Hours),[Xml.XmlDateTimeSerializationMode]::Utc) -replace '\.\d+Z$','Z')"
  }
}
function Get-ContainerUrl {
  [CmdletBinding()]
  [OutputType([string])]
  param([switch]$Registry)
  process {
    if ($Registry) {
      # Output 'registry' URL using cached 'Hostname' value
      $Script:Falcon.Hostname -replace 'api(\.us-2|\.eu-1|laggar\.gcw)?','registry'
    } else {
      # Output 'container-upload' URL using cached 'Hostname' value
      if ($Script:Falcon.Hostname -match 'api\.crowdstrike') {
        $Script:Falcon.Hostname -replace 'api','container-upload.us-1'
      } else {
        $Script:Falcon.Hostname -replace 'api','container-upload'
      }
    }
  }
}
function Get-EndpointFormat {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Endpoint)
  begin { [hashtable]$Output = @{} }
  process {
    # Define endpoint payload/parameters using 'format.json'
    [string[]]$Array = try { $Endpoint -split ':',2 } catch {}
    if ($Array) {
      @($Script:Falcon.Format.($Array[0]).($Array[1]).PSObject.Properties).Where({$null -ne $_.Value}).foreach{
        $Output[$_.Name] = if ($_.Value -is [PSCustomObject]) {
          $Value = @{}
          @($_.Value.PSObject.Properties).foreach{ $Value[$_.Name] = $_.Value }
          $Value
        } else {
          $_.Value
        }
      }
    }
  }
  end { if ($Output) { $Output }}
}
function Get-ParamSet {
  [CmdletBinding()]
  param(
    [string]$Endpoint,
    [hashtable]$Headers,
    [object]$UserInput,
    [hashtable]$Format,
    [int32]$Max,
    [string]$HostUrl
  )
  begin {
    # Get baseline switch and endpoint parameters
    $Switches = @{}
    if ($UserInput) {
      $UserInput.GetEnumerator().Where({$_.Key -match '^(All|Detailed|Total)$'}).foreach{
        $Switches.Add($_.Key,$_.Value)
      }
    }
    $Base = @{
      Path = if ($HostUrl) {
        [string]::Concat($HostUrl,$Endpoint.Split(':',2)[0])
      } else {
        [string]::Concat($Script:Falcon.Hostname,$Endpoint.Split(':',2)[0])
      }
      Method = $Endpoint.Split(':')[1]
      Headers = $Headers
    }
    if (!$Max) {
      $IdCount = if ($UserInput.ids) {
        # Find maximum number of 'ids' parameter using equivalent of 500 32-character ids
        $Pmax = ($UserInput.ids | Measure-Object -Maximum -Property Length -EA 0).Maximum
        if ($Pmax) { [Math]::Floor([decimal](18500/($Pmax + 5))) }
      }
      # Output maximum
      $Max = if ($IdCount -and $IdCount -lt 500) {
        $IdCount
      } elseif ($UserInput.composite_ids) {
        # Use 1000 for 'composite_ids'
        1000
      } else {
        # Default to 500
        500
      }
    }
    # Get 'Content' from user input and find identifier field
    $Content = Build-Content -UserInput $UserInput -Format $Format
    [string]$Field = if ($Content.Body) {
      if ($Content.Body.composite_ids) {
        'composite_ids'
      } elseif ($Content.Body.ids) {
        'ids'
      } elseif ($Content.Body.samples) {
        'samples'
      }
    }
  }
  process {
    if ($Content.Query -and ($Content.Query | Measure-Object).Count -gt $Max) {
      Write-Log 'Get-ParamSet' "Creating groups of $Max query values"
      for ($i = 0; $i -lt ($Content.Query | Measure-Object).Count; $i += $Max) {
        # Split 'Query' values into groups
        $Split = $Switches.Clone()
        $Split.Add('Endpoint',$Base.Clone())
        $Split.Endpoint.Path += if ($Split.Endpoint.Path -match '\?') {
          "&$($Content.Query[$i..($i + ($Max - 1))] -join '&')"
        } else {
          "?$($Content.Query[$i..($i + ($Max - 1))] -join '&')"
        }
        $Content.GetEnumerator().Where({$_.Key -ne 'Query' -and $_.Value}).foreach{
          # Add values other than 'Query'
          $Split.Endpoint.Add($_.Key,$_.Value)
        }
        ,$Split
      }
    } elseif ($Content.Body -and $Field -and ($Content.Body.$Field | Measure-Object).Count -gt $Max) {
      Write-Log 'Get-ParamSet' "Creating groups of $Max '$Field' values"
      for ($i = 0; $i -lt ($Content.Body.$Field | Measure-Object).Count; $i += $Max) {
        # Split 'Body' content into groups using '$Field'
        $Split = $Switches.Clone()
        $Split.Add('Endpoint',$Base.Clone())
        $Split.Endpoint.Add('Body',@{ $Field = $Content.Body.$Field[$i..($i + ($Max - 1))] })
        $Content.GetEnumerator().Where({$_.Value}).foreach{
          # Add values other than 'Body.$Field'
          if ($_.Key -eq 'Query') {
            $Split.Endpoint.Path += if ($Split.Endpoint.Path -match '\?') {
              "&$($_.Value -join '&')"
            } else {
              "?$($_.Value -join '&')"
            }
          } elseif ($_.Key -eq 'Body') {
            ($_.Value).GetEnumerator().Where({$_.Key -ne $Field}).foreach{
              $Split.Endpoint.Body.Add($_.Key,$_.Value)
            }
          } else {
            $Split.Endpoint.Add($_.Key,$_.Value)
          }
        }
        ,$Split
      }
    } else {
      # Use base parameters, add content and output single parameter set
      $Switches.Add('Endpoint',$Base.Clone())
      if ($Content) {
        $Content.GetEnumerator().foreach{
          if ($_.Key -eq 'Query') {
            $Switches.Endpoint.Path += if ($Switches.Endpoint.Path -match '\?') {
              "&$($_.Value -join '&')"
            } else {
              "?$($_.Value -join '&')"
            }
          } else {
            $Switches.Endpoint.Add($_.Key,$_.Value)
          }
        }
      }
      $Switches
    }
  }
}
function Get-RtrCommand {
  [CmdletBinding()]
  param(
    [string]$Command,
    [switch]$ConfirmCommand,
    [ValidateSet('ReadOnly','Responder','Admin')]
    [string]$Permission
  )
  begin {
    # Update 'Permission' to include lower level permission(s)
    [string[]]$Permission = switch ($Permission) {
      'ReadOnly' { 'ReadOnly' }
      'Responder' { 'ReadOnly','Responder' }
      'Admin' { 'ReadOnly','Responder','Admin' }
    }
  }
  process {
    # Create table of Real-time Response commands organized by permission level
    $Index = @{}
    @($null,'Responder','Admin').foreach{
      $Key = if ($_ -eq $null) { 'ReadOnly' } else { $_ }
      $Index[$Key] = (Get-Command "Invoke-Falcon$($_)Command").Parameters.GetEnumerator().Where({
        $_.Key -eq 'Command'}).Value.Attributes.ValidValues
    }
    # Filter 'Responder' and 'Admin' to unique command(s)
    $Index.Responder = @($Index.Responder).Where({$Index.ReadOnly -notcontains $_})
    $Index.Admin = @($Index.Admin).Where({$Index.ReadOnly -notcontains $_ -and $Index.Responder -notcontains $_})
    if ($Command) {
      # Determine command to invoke using $Command and permission level
      [string]$Result = if ($Command -eq 'runscript') {
        # Force 'Admin' for 'runscript' command
        'Invoke-FalconAdminCommand'
      } else {
        $Index.GetEnumerator().Where({$_.Value -contains $Command}).foreach{
          if ($_.Key -eq 'ReadOnly') { 'Invoke-FalconCommand' } else { "Invoke-Falcon$($_.Key)Command" }
        }
      }
      if ($ConfirmCommand) { $Result -replace 'Invoke','Confirm' } else { $Result }
    } elseif ($Permission) {
      # Return available Real-time Response commands by permission
      $Index.GetEnumerator().Where({$Permission -contains $_.Key}).Value
    } else {
      # Return all available Real-time Response commands
      @($Index.Values).foreach{ $_ }
    }
  }
}
function Get-RtrResult {
  [CmdletBinding()]
  param([object[]]$Object,[object[]]$Output)
  begin {
    # Real-time Response fields to capture from results
    [string[]]$RtrFields = 'aid','batch_get_cmd_req_id','batch_id','cloud_request_id','complete','errors',
      'error_message','name','offline_queued','progress','queued_command_offline','session_id','sha256',
      'size','status','stderr','stdout','task_id'
  }
  process {
    foreach ($Result in $Object) {
      # Update 'Output' with populated result(s) from 'Object'
      @($Result.PSObject.Properties).Where({$RtrFields -contains $_.Name}).foreach{
        $Name = if ($_.Name -eq 'task_id') {
          # Rename 'task_id' to 'cloud_request_id'
          'cloud_request_id'
        } elseif ($_.Name -eq 'queued_command_offline') {
          # Rename 'queued_command_offline' to 'offline_queued'
          'offline_queued'
        } else {
          $_.Name
        }
        $Value = if (($_.Value -is [object[]]) -and ($_.Value[0] -is [string])) {
          # Convert array result into string
          $_.Value -join ', '
        } elseif ($_.Value.code -and $_.Value.message) {
          # Convert error code and message into string
          (($_.Value).foreach{ "$($_.code): $($_.message)" }) -join ', '
        } else {
          $_.Value
        }
        # Update 'Output' with result using 'aid' or 'session_id'
        $Match = if ($Result.aid) { 'aid' } else { 'session_id' }
        if ($Result.$Match) {
          @($Output).Where({$Result.$Match -eq $_.$Match}).foreach{ Set-Property $_ $Name $Value }
        }
      }
    }
  }
  end { return $Output }
}
function Invoke-Falcon {
  [CmdletBinding(SupportsShouldProcess)]
  param(
    [string]$Command,
    [string]$Endpoint,
    [hashtable]$Headers,
    [object]$UserInput,
    [hashtable]$Format,
    [switch]$RawOutput,
    [int32]$Max,
    [string]$HostUrl,
    [switch]$BodyArray,
    [string]$JsonBody
  )
  begin {
    function Invoke-Loop ([hashtable]$Splat,[object]$Object,[int]$Int,[switch]$Raw) {
      do {
        # Determine next offset value
        [string[]]$Next = if ($Object.after) {
          @('after',$Object.after)
        } elseif ($Object.next) {
          @('offset',$Object.next)
        } elseif ($Object.next_token) {
          @('next_token',$Object.next_token)
        } elseif ($null -ne $Object.offset) {
          $Value = if ($Object.offset -match '^\d{1,}$') { $Int } else { $Object.offset }
          @('offset',$Value)
        }
        if ($Next) {
          # Clone parameters and make request
          $Clone = Set-LoopParam $Splat $Next
          if ($Script:Falcon.Expiration -le (Get-Date).AddSeconds(240)) {
            # Refresh authorization token when required
            if ($PSCmdlet.ShouldProcess('Request-FalconToken','Get-ApiCredential')) { Request-FalconToken }
          }
          [string]$Target = New-ShouldMessage $Clone.Endpoint
          if ($PSCmdlet.ShouldProcess($Target,$Operation)) {
            $Script:Falcon.Api.Invoke($Clone.Endpoint) | ForEach-Object {
              # Output result, update pagination and received count
              $Object = $_.meta.pagination
              if ($Raw) {
                Write-Request $Clone $_ -Raw -OutVariable Output
              } else {
                Write-Request $Clone $_ -OutVariable Output
              }
              [int]$Int += if ($Raw) {
                # Use 'resources' to count for 'RawOutput'
                ($Output.resources | Measure-Object).Count
              } else {
                ($Output | Measure-Object).Count
              }
              if ($null -ne $Object.total) { Write-Log $Command ("Retrieved {0} of {1}" -f $Int,$Object.total) }
            }
          }
        } elseif ($Int -lt $Object.total) {
          throw ("Aborted due to missing pagination token. [Retrieved {0} of {1}]" -f $Int,$Object.total)
        }
      } while ($null -ne $Object.total -and $null -ne $Next -and $Int -lt $Object.total)
    }
    function Set-LoopParam ([hashtable]$Splat,[string[]]$Next) {
      $Clone = $Splat.Clone()
      $Clone.Endpoint = $Splat.Endpoint.Clone()
      $Clone.Endpoint.Path = if ($Clone.Endpoint.Path -match "$($Next[0])=\d{1,}") {
        # If offset was input, continue from that value
        $Current = [regex]::Match($Clone.Endpoint.Path,'offset=(\d+)(^&)?').Captures.Value
        $Next[1] += [int]$Current.Split('=')[-1]
        $Clone.Endpoint.Path -replace $Current,($Next -join '=')
      } elseif ($Clone.Endpoint.Path -eq $Splat.Endpoint.Path -and $Clone.Endpoint.Path -notmatch '\?') {
        # Add pagination
        $Clone.Endpoint.Path,($Next -join '=') -join '?'
      } else {
        # Append pagination
        $Clone.Endpoint.Path,($Next -join '=') -join '&'
      }
      $Clone
    }
    function Write-Request {
      [CmdletBinding()]
      param([hashtable]$Splat,[object]$Object,[switch]$Raw)
      if ($Raw) {
        # Return entire result for 'RawOutput'
        if ($Object.meta -and !$Object.errors) {
          # Output 'meta' to verbose stream and capture 'trace_id' for a successful response
          $Message = (@($Object.meta.PSObject.Properties).foreach{
            if ($_.Name -eq 'pagination') {
              @($_.Value.PSObject.Properties).foreach{ ('pagination',$_.Name -join '.'),$_.Value -join '=' }
            } else {
              $_.Name,$_.Value -join '='
            }
          }) -join ', '
          Write-Log 'Write-Request' ($Message -join ' ')
        }
        $Object
      } else {
        [boolean]$NoDetail = if ($Splat.Endpoint.Path -match '(/combined/|/rule-groups-full/)') {
          # Determine if endpoint requires a secondary 'Detailed' request
          $true
        } else {
          $false
        }
        if ($Splat.Detailed -eq $true -and $NoDetail -eq $false) {
          # Get 'Detailed' result
          $Output = Write-Result $Object
          if ($Output.aid) { & $Command -Id $Output.aid } elseif ($Output) { & $Command -Id $Output }
        } else {
          Write-Result $Object
        }
      }
    }
    if (!$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -or !$Script:Falcon.Hostname) {
      # Force initial authorization token request
      if ($PSCmdlet.ShouldProcess('Request-FalconToken','Get-ApiCredential')) { Request-FalconToken }
    }
    # Add 'Format' using 'format.json' when not supplied
    if (!$PSBoundParameters.Format) { $PSBoundParameters['Format'] = Get-EndpointFormat $Endpoint }
    # Gather request parameters and split into groups
    [string[]]$Exclude = 'BodyArray','Command','JsonBody','RawOutput'
    $GetParam = @{}
    $PSBoundParameters.GetEnumerator().Where({$Exclude -notcontains $_.Key}).foreach{
      $GetParam.Add($_.Key,$_.Value)
    }
    # Add 'Accept: application/json' when undefined
    if (!$GetParam.Headers) { $GetParam.Add('Headers',@{}) }
    if (!$HostUrl -and !$GetParam.Headers.Accept) { $GetParam.Headers.Add('Accept','application/json') }
    if ($PSBoundParameters.Format.Body -and !$GetParam.Headers.ContentType) {
      # Add 'ContentType: application/json' when undefined and 'Body' is present
      $GetParam.Headers.Add('ContentType','application/json')
    }
    if ($UserInput.All -eq $true -and !$UserInput.Limit) {
      # Add maximum 'Limit' when not present and using 'All'
      $Limit = (Get-Command $Command).ParameterSets.Where({$_.Name -eq $Endpoint}).Parameters.Where({
        $_.Name -eq 'Limit'}).Attributes.MaxRange
      if ($Limit) { $UserInput.Add('Limit',$Limit) }
    }
  }
  process {
    Get-ParamSet @GetParam | ForEach-Object {
      [string]$Operation = $_.Endpoint.Method.ToUpper()
      if ($JsonBody) {
        # Add 'JsonBody' directly as the request body, when present
        $_.Endpoint['Body'] = $JsonBody
        if (!$_.Endpoint.Headers.ContentType) { $_.Endpoint.Headers.Add('ContentType','application/json') }
      } elseif ($_.Endpoint.Headers.ContentType -eq 'application/json' -and $_.Endpoint.Body) {
        $_.Endpoint.Body = if ($BodyArray) {
          # Force Json array when 'BodyArray' is present
          ConvertTo-Json @($_.Endpoint.Body) -Depth 32 -Compress
        } else {
          # Convert body to Json
          ConvertTo-Json $_.Endpoint.Body -Depth 32 -Compress
        }
      }
      [string]$Target = New-ShouldMessage $_.Endpoint
      if ($PSCmdlet.ShouldProcess($Target,$Operation)) {
        if ($Script:Falcon.Expiration -le (Get-Date).AddSeconds(240)) { Request-FalconToken }
        try {
          Write-Log $Command $Endpoint
          $Request = $Script:Falcon.Api.Invoke($_.Endpoint)
          if ($Request) {
            # Capture pagination for 'Total' and 'All'
            $Pagination = $Request.meta.pagination
            if ($null -ne $Pagination.total -and $_.Total -eq $true) {
              # Output 'Total'
              $Pagination.total
            } else {
              if ($RawOutput) {
                # Return entire result for 'RawOutput'
                Write-Request $_ $Request -Raw -OutVariable Result
              } else {
                Write-Request $_ $Request -OutVariable Result
              }
              if ($Result -and $_.All -eq $true) {
                # Repeat request(s)
                [int]$Count = if ($RawOutput) {
                  # Count 'resources' for 'RawOutput'
                  ($Result.resources | Measure-Object).Count
                } else {
                  ($Result | Measure-Object).Count
                }
                if ($Pagination.total -and $Count -lt $Pagination.total) {
                  Write-Log $Command "Retrieved $Count of $($Pagination.total)"
                  if ($RawOutput) {
                    Invoke-Loop $_ $Pagination $Count -Raw
                  } else {
                    Invoke-Loop $_ $Pagination $Count
                  }
                }
              }
            }
          }
        } catch {
          $PSCmdlet.WriteError($_)
        }
      }
    }
  }
}
function Invoke-UpdateCheck {
  param(
    [Parameter(Mandatory,Position=1)]
    [string]$BasePath
  )
  function Test-GalleryInstall {
    if (Get-Command -Name Get-InstalledModule -EA 0) {
      # Check whether PSFalcon was installed using PSGallery
      if ((Get-InstalledModule -Name PSFalcon -EA 0).Repository -eq 'PSGallery') { $true } else { $false }
    } else {
      $false
    }
  }
  function Write-UpdateJson {
    param(
      [Parameter(Mandatory,Position=1)]
      [string]$Path,
      [Parameter(Mandatory,Position=2)]
      [boolean]$Connection,
      [Parameter(Mandatory,Position=3)]
      [int64]$Timestamp,
      [Parameter(Mandatory,Position=4)]
      [string]$Version
    )
    # Create 'update_check.json'
    try {
      [PSCustomObject]@{
        psgallery_connection = $Connection
        timestamp = $Timestamp
        version = $Version
      } | ConvertTo-Json -Compress -EA 0 > $Path
      Write-Log 'Invoke-UpdateCheck' ('Created "{0}"' -f $Path)
    } catch {
      Write-Log 'Invoke-UpdateCheck' ('Failed to create "{0}"' -f $Path)
    }
  }
  function Write-VersionWarning ([string]$String) {
    # Write warning message notifying that a new release is available
    Write-Warning ('PSFalcon is out of date. Release v{0} is available on the PowerShell Gallery.' -f $String)
  }
  # Check for write access to 'update_check.json'
  $FilePath = Join-Path $BasePath update_check.json
  $Access = try { [IO.File]::OpenWrite($FilePath).Close() } catch { $false }
  if ($Access -ne $false) {
    # Import 'update_check.json'
    $Check = try { Get-Content -Path $FilePath -EA 0 | ConvertFrom-Json -EA 0 } catch { $null }
    $InstVer = try { (Show-FalconModule).ModuleVersion.Split(' ',2)[0] -replace '^v',$null } catch { $null }
    $WeekAgo = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - 604800000
    if (!$Check) {
      # Create 'update_check.json'
      Write-UpdateJson $FilePath (Test-GalleryInstall) $WeekAgo $InstVer
    } elseif ($Check.psgallery_connection -eq $true) {
      if ($InstVer -lt $Check.version) {
        # Notify of new release on PSGallery
        Write-VersionWarning $Check.version
      } elseif ($WeekAgo -lt $Check.timestamp) {
        # Check PSGallery every 7 days
        $Gallery = try { Find-Module -Name PSFalcon -Repository PSGallery -EA 0 } catch { $null }
        $Timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        if (!$Gallery) {
          # Create 'update_check.json' with 'psgallery_connection' of $false
          Write-UpdateJson $FilePath $false $Timestamp $InstVer
        } else {
          # Overwrite 'update_check.json' with PSGallery version
          Write-UpdateJson $FilePath $true $Timestamp $Gallery.Version.ToString()
          if ($Check.version -lt $Gallery.version) {
            # Notify of new release on PSGallery
            Write-VersionWarning $Gallery.Version.ToString()
          }
        }
      }
    }
  } else {
    Write-Log 'Invoke-UpdateCheck' 'Unable to create update file.'
  }
}
function New-ShouldMessage {
  [CmdletBinding()]
  [OutputType([string[]])]
  param ([hashtable]$Object)
  process {
    try {
      $Output = [PSCustomObject]@{}
      if ($Object.Path) {
        [string]$Path = $Object.Path
        if ($Path -match $Script:Falcon.Hostname) {
          # Add 'Hostname' when using cached hostname value
          Set-Property $Output Hostname $Script:Falcon.Hostname
          $Path = $Path -replace $Script:Falcon.Hostname,$null
        }
        if ($Path -match '\?') {
          # Add 'Path' without query values, and 'Query' as an array
          [string[]]$Array = $Path -split '\?'
          [string[]]$Query = $Array[-1] -split '&'
          Set-Property $Output Path $Array[0]
          if ($Query) { Set-Property $Output Query $Query }
        } else {
          Set-Property $Output Path $Path
        }
      }
      if ($Object.Headers) {
        # Add 'Headers' value
        [string]$Header = ($Object.Headers.GetEnumerator().foreach{
          $_.Key,$_.Value -join '=' } -join ', ')
        if ($Header) { Set-Property $Output Headers $Header }
      }
      if ($Object.Body -and $Object.Headers.ContentType -eq 'application/json') {
        # Add 'Body' value
        Set-Property $Output Body $Object.Body
      }
      if ($Object.Formdata) {
        # Add 'Formdata' value
        [string]$Formdata = try { $Object.Formdata | ConvertTo-Json -Depth 8 } catch {}
        if ($Formdata) { Set-Property $Output Formdata $Formdata }
      }
      "`r`n",($Output | Format-List | Out-String).Trim(),"`r`n" -join "`r`n"
    } catch {}
  }
}
function Remove-EmptyValue {
  param(
    [object]$Object,
    [string[]]$String
  )
  foreach ($i in $Object.PSObject.Properties.Name) {
    if (($Object.$i | Measure-Object).Count -gt 1) {
      # Remove empty sub-properties
      @($Object.$i).foreach{ Remove-EmptyValue $_ }
    }
    if ($String -notcontains $i -and [string]::IsNullOrEmpty($Object.$i)) {
      # Remove empty properties, except those defined by 'String'
      [void]$Object.PSObject.Properties.Remove($i)
    }
  }
}
function Select-CertificateProperty {
  [CmdletBinding()]
  [OutputType([PSCustomObject])]
  param(
    [Parameter(Mandatory,Position=1)]
    [object]$Object
  )
  try {
    # Select required fields when submitting a certificate for a certificate-based exclusion
    [string[]]$Select = 'issuer','serial','subject','thumbprint','valid_from','valid_to'
    $Output = [PSCustomObject]$Object | Select-Object $Select
    if ($Output) {
      @($Select).foreach{
        if (!$Output.$_ -or $null -eq $Output.$_) { throw "Certificate missing required property '$_'." }
      }
      $Output
    }
  } catch {
    throw $_
  }
}
function Select-Property {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory,Position=1)]
    [object[]]$Object,
    [Parameter(Mandatory,Position=2)]
    [string]$Parameter,
    [Parameter(Mandatory,Position=3)]
    [string]$Pattern,
    [Parameter(Mandatory,Position=4)]
    [string]$Command,
    [Parameter(Mandatory,Position=5)]
    [string]$Property,
    [Parameter(Position=6)]
    [string]$Parent
  )
  function Select-StringMatch ([string[]]$String,[string]$Parameter,[string]$Pattern,[string]$Command) {
    @($String).foreach{
      if ($_ -notmatch $Pattern) {
        # Output error record for eventual return
        [string]$Message = "Cannot validate argument on parameter '$Parameter'.",
          ('The argument "{0}" does not match the "{1}" pattern.' -f $_,$Pattern),
          ('Supply an argument that matches "{0}" and try the command again.' -f $Pattern) -join ' '
        [System.Management.Automation.ErrorRecord]::New(
          [Exception]::New($Message),
          'ParameterArgumentValidationError',
          [System.Management.Automation.ErrorCategory]::InvalidData,
          $_
        )
      } elseif ($_ -match $Pattern) {
        # Output matching string value
        $_
      }
    }
  }
  @($Object).foreach{
    if ($Parent -and $_.$Parent.$Property) {
      # Check 'Property' under 'Parent' for matching value
      @($_.$Parent.$Property).foreach{ Select-StringMatch $_ $Parameter $Pattern $Command }
    } elseif ($_.$Property) {
      # Check 'Property' for matching value
      @($_.$Property).foreach{ Select-StringMatch $_ $Parameter $Pattern $Command }
    } elseif (![string]::IsNullOrEmpty($_)) {
      # Treat value as [string] and check for match
      Select-StringMatch $_ $Parameter $Pattern $Command
    }
  }
}
function Set-Property {
  [CmdletBinding()]
  [OutputType([void])]
  param([object]$Object,[string]$Name,[object]$Value)
  process {
    if ($Object.PSObject.Properties.Item($Name)) {
      # Update existing property
      $Object.$Name = $Value
    } else {
      # Add property to [PSCustomObject]
      $Object.PSObject.Properties.Add((New-Object PSNoteProperty($Name,$Value)))
    }
  }
}
function Start-RtrUpdate {
  [CmdletBinding()]
  [OutputType([int32])]
  param(
    [Parameter(Mandatory=$true,Position=1)]
    [object]$Object,
    [Parameter(Mandatory=$true,Position=2)]
    [int]$Int
  )
  begin {
    # Script to run as background job for Real-time Response session refresh
    $ScriptBlock = {
      param(
        [string]$BaseAddress,
        [string]$ApiClient,
        [string]$Token,
        [int]$ExpiresIn,
        [int]$Timeout,
        [string]$Id
      )
      $Expiration = (Get-Date).AddSeconds($ExpiresIn)
      do {

        ### add rate limits for 429 during token request/session refresh

        Start-Sleep -Seconds ($Timeout - 10)
        if ($Expiration -le (Get-Date).AddSeconds(240)) {
          # Renew authorization token for background job
          $Param = @{
            Uri = $BaseAddress,'oauth2/token' -join '/'
            Method = 'post'
            Headers = @{
              Accept = 'application/json'
              'Content-Type' = 'application/x-www-form-urlencoded'
            }
            Body = $ApiClient
          }
          $Request = Invoke-RestMethod @Param -UseBasicParsing
          if ($Request.expires_in) {
            Write-Output ('New token received. Expires in {0} seconds.' -f $Request.expires_in)
          }
          Set-Variable -Name Expiration -Value (Get-Date).AddSeconds($Request.expires_in)
          Set-Variable -Name Token -Value ($Request.token_type,$Request.access_token -join ' ')
        }
        if ($Id -and $Token) {
          # Refresh Real-time Response session before timeout
          $Param = @{
            Uri = if ($Id -match '^[a-fA-F0-9]{32}$') {
              $BaseAddress,('real-time-response/entities/sessions/v1?timeout',$Timeout -join '=') -join '/'
            } else {
              $BaseAddress,('real-time-response/combined/batch-init-session/v1?timeout',
                $Timeout -join '=') -join '/'
            }
            Method = 'post'
            Headers = @{ Accept = 'application/json'; Authorization = $Token; 'Content-Type' = 'application/json' }
            Body = if ($Id -match '^[a-fA-F0-9]{32}$') {
              @{ device_id = $Id } | ConvertTo-Json -Compress
            } else {
              @{ batch_id = $Id } | ConvertTo-Json -Compress
            }
          }
          $Request = Invoke-RestMethod @Param -UseBasicParsing
          $Value = if ($Request.resources.batch_id) {
            # Re-capture 'batch_id'
            $Request.resources.batch_id
          } elseif ($Request.resources.session_id) {
            # Use existing 'device_id' value
            $Id
          }
          Set-Variable -Name Id -Value $Value
          if ($Id -match '^[a-fA-F0-9]{32}$') {
            # Notify of successful session refresh
            Write-Output ((Get-Date -Format u),
              ('Refreshed session {0}' -f $Request.resources.session_id) -join ': ')
          } elseif ($Id) {
            Write-Output ((Get-Date -Format u),
              ('Refreshed batch session {0}' -f $Request.resources.batch_id) -join ': ')
          }
        }
      } while ($Expiration -and $Id -and $Token)
    }
    Stop-RtrUpdate
  }
  process {
    # Start background job to refresh Real-time Response session
    [string]$Name = 'psfalcon-rtr',(Get-Date -Format FileDateTime) -join '_'
    [string]$Id = if ($Object.batch_id) { $Object.batch_id } elseif ($Object.aid) { $Object.aid }
    [string[]]$ApiClient = ('client_id',$Script:Falcon.ClientId -join '='),('client_secret',
      $Script:Falcon.ClientSecret -join '=')
    if ($Script:Falcon.MemberCid) { $ApiClient += 'member_cid',$Script:Falcon.MemberCid -join '=' }
    [string[]]$ArgList = @(
      # Capture required arguments for background job
      $Script:Falcon.Hostname,
      ($ApiClient -join '&'),
      $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization.ToString(),
      ($Script:Falcon.Expiration-(Get-Date)).TotalSeconds,
      $Int,
      $Id
    )
    $Output = Start-Job -Name $Name -ScriptBlock $ScriptBlock -ArgumentList $ArgList
    if ($Output) {
      Write-Log 'Start-RtrUpdate' "Started job: $($Output.Name)"
      $Output.Id
    }
  }
}
function Stop-RtrUpdate {
  [CmdletBinding()]
  [OutputType([void])]
  param([int32]$Int)
  process {
    if ($Int) {
      $Job = Get-Job -Id $Int -EA 0
      if ($Job) {
        # Kill background job by id
        Remove-Job -Id $Job.Id -Force
        if (Get-Job -Id $Job.Id -EA 0) {
          Write-Log 'Stop-RtrUpdate' "Failed to terminate job: $($Job.Name)"
        } else {
          Write-Log 'Stop-RtrUpdate' "Terminated job: $($Job.Name)"
        }
      }
    }
    @(Get-Job).Where({$_.Name -match '^psfalcon-rtr_' -and $_.State -eq 'Completed'}).foreach{
      # Remove 'Completed' background jobs
      Remove-Job -Id $_.Id
      if (Get-Job -Id $_.Id -EA 0) {
        Write-Log 'Stop-RtrUpdate' "Failed to remove job: $($_.Name)"
      } else {
        Write-Log 'Stop-RtrUpdate' "Removed job: $($_.Name)"
      }
    }
  }
}
function Test-ActionParameter {
  [CmdletBinding()]
  [OutputType([hashtable])]
  param(
    [hashtable]$Hashtable,
    [string[]]$String,
    [switch]$Incident
  )
  if ($Hashtable) {
    $Hashtable.GetEnumerator().foreach{
      if ($String -and $String -notcontains $_.Key) {
        # Verify that each 'Action' is using a valid 'name'
        throw ('"{0}" is not a valid action name.' -f $_.Key)
      } elseif ($_.Key -eq 'update_status') {
        if ($Incident -and $_.Value -match '^(20|new|25|reopened|30|in_progress|40|closed)$') {
          # Verify that 'update_status' is using a proper string value when working with incidents
          $_.Value = switch -Regex ($_.Value) {
            '20|new' { '20' }
            '25|reopened' { '25' }
            '30|in_progress' { '30' }
            '40|closed' { '40' }
          }
        } elseif ($_.Value -notmatch '^(new|reopened|in_progress|closed)$') {
          throw "Valid values for 'update_status': 'closed', 'in_progress', 'new', 'reopened'."
        }
      }
      return @{ name = $_.Key; value = $_.Value }
    }
  }
}
function Test-FqlStatement {
  [CmdletBinding()]
  [OutputType([boolean])]
  param([Parameter(Mandatory)][string]$String)
  begin {
    $Pattern = [regex]("(?<FqlProperty>[\w\.]+):(?<FqlOperator>(!~?|~|(>|<)=?|\*)?)(?<FqlValue>[\w\d\s\.\-\*\[\]" +
      "\\,'`":]+)")
  }
  process {
    if ($String -notmatch $Pattern) {
      # Error when 'filter' does not match $Pattern
      throw "'$String' is not a valid Falcon Query Language statement."
    } else {
      $true
    }
  }
}
function Test-OutFile {
  [CmdletBinding()]
  [OutputType([hashtable])]
  param([string]$Path)
  process {
    if (!$Path) {
      @{
        # Generate parameters for 'Write-Error' if 'Path' is not present
        Message = "Missing required parameter 'Path'."
        Category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
      }
    } elseif ($Path -is [string] -and ![string]::IsNullOrEmpty($Path) -and (Test-Path $Path) -eq $true) {
      @{
        # Generate parameters for 'Write-Error' if 'Path' already exists
        Message = "An item with the specified name $Path already exists."
        Category = [System.Management.Automation.ErrorCategory]::WriteError
        TargetName = $Path
      }
    }
  }
}
function Test-RegexValue {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$String)
  begin {
    $RegEx = @{
      md5 = [regex]'^[A-Fa-f0-9]{32}$'
      sha256 = [regex]'^[A-Fa-f0-9]{64}$'
      ipv4 = [regex]('((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])')
      ipv6 = [regex]'^[0-9a-fA-F]{1,4}:'
      domain = [regex]'^(https?://)?((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$'
      email = [regex]"^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$"
      tag = [regex]'^[-\w\d_/]+$'
    }
  }
  process {
    $Output = ($RegEx.GetEnumerator()).foreach{
      if ($String -match $_.Value) {
        if ($_.Key -match '^(ipv4|ipv6)$') {
          # Use initial RegEx match, then validate IP and return type
          if (($String -as [System.Net.IPAddress] -as [bool]) -eq $true) { $_.Key }
        } else {
          # Return type
          $_.Key
        }
      }
    }
  }
  end {
    if ($Output) {
      Write-Log 'Test-RegexValue' (($Output | Out-String).Trim(),$String -join ': ')
      $Output
    }
  }
}
function Wait-RtrCommand {
  [CmdletBinding()]
  [OutputType([object])]
  param([object]$Object,[string]$String)
  begin { $Confirm = $String -replace '^Invoke','Confirm' }
  process {
    Start-Sleep -Seconds 5
    do {
      # Wait for the result of single-host Real-time Response command
      $Object = @($Object | & $Confirm).foreach{
        if ($_.task_id -and $_.complete -eq $false) { Write-Log $String "Waiting for task_id: $($_.task_id)" }
        $_
      }
      if ($Object -and $Object.complete -eq $false) { Start-Sleep -Seconds 20 }
    } while ($Object -and $Object.complete -eq $false)
  }
  end { $Object }
}
function Wait-RtrGet {
  [CmdletBinding()]
  [OutputType([object])]
  param([object]$Object,[string]$String)
  process {
    Start-Sleep -Seconds 5
    if ($Object.batch_get_cmd_req_id) {
      do {
        # Wait for the result of multi-host Real-time Response 'get' command
        $Request = $Object | Confirm-FalconGetFile
        if (!$Request) {
          Write-Log $String "Waiting for batch_get_cmd_req_id: $($Object.batch_get_cmd_req_id)"
          Start-Sleep -Seconds 20
        }
      } until ($Request)
      $Request
    } else {
      do {
        # Wait for the result of single-host Real-time Response 'get' command
        $Object = @($Object | Confirm-FalconGetFile).Where({
          $_.cloud_request_id -eq $Object.cloud_request_id
        }).foreach{
          if (!$_.deleted_at -and $_.complete -eq $false) {
            Write-Log $String ('Waiting for cloud_request_id:',$_.cloud_request_id,
              ('[{0} {1}]' -f ($_.stage),($_.progress/1).ToString("P")) -join ' ')
          }
          $_
        }
        if ($Object.Where({!$_.deleted_at -and $_.complete -eq $false})) { Start-Sleep -Seconds 20 }
      } while ($Object.Where({!$_.deleted_at -and $_.complete -eq $false}))
    }
  }
  end { $Object }
}
function Write-Result {
  [CmdletBinding()]
  param([object]$Json)
  process {
    if ($Json) {
      if ($Json.meta) {
        # Output 'meta' to verbose stream and capture 'trace_id'
        $Message = (@($Json.meta.PSObject.Properties).foreach{
          if ($_.Name -eq 'pagination') {
            @($_.Value.PSObject.Properties).foreach{ ('pagination',$_.Name -join '.'),$_.Value -join '=' }
          } else {
            $_.Name,$_.Value -join '='
          }
        }) -join ', '
        Write-Log 'Write-Result' ($Message -join ' ')
      }
      if ($Json.PSObject.Properties.Where({$_.Name -ne 'meta' -and $null -ne $_.Value}) -or
      $Json.meta.pagination.total -eq 0 -and !$Json.meta.reqid) {
        # Remove 'meta' when other sub-properties are populated, or when pagination.total equals 0
        [void]$Json.PSObject.Properties.Remove('meta')
      }
      @($Json.PSObject.Properties).Where({$_.Name -eq 'errors' -and $_.Value}).foreach{
        @($_.Value).foreach{
          # Output 'errors' to error stream as Json string
          $PSCmdlet.WriteError(
            [System.Management.Automation.ErrorRecord]::New(
              [Exception]::New((ConvertTo-Json $_ -Compress)),
              $Json.meta.trace_id,
              [System.Management.Automation.ErrorCategory]::InvalidResult,
              $Request
            )
          )
        }
      }
      [void]$Json.PSObject.Properties.Remove('errors')
      [string[]]$FieldList = @($Json.PSObject.Properties).Where({
        # Select sub-properties in response not named 'extensions'
        $_.Name -ne 'extensions' -and $null -ne $_.Value
      }).foreach{ $_.Name }
      if (($FieldList | Measure-Object).Count -gt 1) {
        # Output full response when multiple sub-properties are present
        $Json
      } elseif (($FieldList | Measure-Object).Count -eq 1) {
        if ($FieldList -eq 'combined' -and $Json.combined.PSObject.Properties.Name -eq 'resources' -and
        ($Json.combined.PSObject.Properties.Name | Measure-Object).Count -eq 1) {
          # Output 'combined.resources' values
          $Json.combined.resources
        } elseif ($FieldList -eq 'resources' -and $Json.resources.PSObject.Properties.Name -eq
        'events' -and ($Json.resources.PSObject.Properties.Name | Measure-Object).Count -eq 1) {
          # Output 'resources.events' values
          $Json.resources.events
        } else {
          # Output value of single sub-property
          $Json.$FieldList
        }
      }
    }
  }
}
function Write-Log {
  [CmdletBinding()]
  param([string]$Command,[string]$String)
  process { $PSCmdlet.WriteVerbose(((Get-Date -Format 'HH:mm:ss'),"[$Command]",$String -join ' ')) }
}