function Search-MalQueryHash {
    <#
    .SYNOPSIS
        Perform a YARA-based MalQuery search for a specific hash
    .DESCRIPTION
        Additional information is available with the -Help parameter
    .LINK
        https://github.com/CrowdStrike/psfalcon
    #>
    [CmdletBinding(DefaultParameterSetName = 'scripts/MalQueryHash')]
    [OutputType()]
    param()
    DynamicParam {
        $Endpoints = @('scripts/MalQueryHash')
        return (Get-Dictionary -Endpoints $Endpoints -OutVariable Dynamic)
    }
    begin {
        $Sleep = 5
        $MaxSleep = 30
        $Search = "Invoke-FalconMalQuery"
        $Confirm = "Get-FalconMalQuery"
    }
    process {
        if ($PSBoundParameters.Help) {
            Get-DynamicHelp -Command $MyInvocation.MyCommand.Name
        }
        else {
            $Param = @{
                Hunt = $true
                YaraRule = "import `"hash`"`nrule SearchHash`n{`ncondition:`nhash.sha256(0, filesize) == " +
                "`"$($PSBoundParameters.Sha256)`"`n}"
                FilterMeta = 'sha256', 'type', 'label', 'family'
            }
            $Request = & $Search @Param

            if ($Request.meta.reqid) {
                $Param = @{
                    QueryIds = $Request.meta.reqid
                    OutVariable = 'Result'
                }
                if ((& $Confirm @Param).meta.status -EQ 'inprogress') {
                    do {
                        Start-Sleep -Seconds $Sleep
                        $i += $Sleep
                    } until (
                        ((& $Confirm @Param).meta.status -NE 'inprogress') -or ($i -ge $MaxSleep)
                    )
                }
                if ($Result.resources) {
                    $Result.resources | Select-Object sha256, filetype, family, label
                } else {
                    $Result.meta | Select-Object reqid, status
                }
            }
            else {
                throw "$($Request.errors.code): $($Request.errors.message)"
            }
        }
    }
}