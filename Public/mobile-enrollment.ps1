function Invoke-FalconMobileAction {
<#
.SYNOPSIS
Trigger on-boarding process for a mobile device
.DESCRIPTION
Requires 'mobile-enrollment:write'.
.PARAMETER Name
Action to perform
.PARAMETER ExpiresAt
Expiration time [default: 30 days]
.PARAMETER Email
Email address
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Mobile-Enrollment
#>
       [CmdletBinding(DefaultParameterSetName='/enrollments/entities/details/v3:post',SupportsShouldProcess)]
       param(
            [Parameter(ParameterSetName='/enrollments/entities/details/v3:post',Mandatory,Position=1)]
            [ValidateSet('enroll','re-enroll',IgnoreCase=$false)]
            [Alias('action_name')]
            [string]$Name,
            [Parameter(ParameterSetName='/enrollments/entities/details/v3:post',Position=2)]
            [Alias('expires_at')]
            [string]$ExpiresAt,
            [Parameter(ParameterSetName='/enrollments/entities/details/v3:post',Mandatory,ValueFromPipeline,
                ValueFromPipelineByPropertyName,Position=3)]
            [ValidateScript({
                if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
            })]
            [Alias('email_addresses')]
            [string[]]$Email
       )
       # 
       begin {
        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{ Query = @('action_name'); Body = @{ root = @('email_addresses','expires_at') }}
        }
        [System.Collections.Generic.List[string]]$List = @()
        if (!$PSBoundParameters.ExpiresAt) { $PSBoundParameters.ExpiresAt = Convert-Rfc3339 720 }
    }
    process { if ($Email) { @($Email).foreach{ $List.Add($_) }}}
    end {
        if ($List) {
            $PSBoundParameters['Email'] = @($List | Select-Object -Unique)
            Invoke-Falcon @Param -Inputs $PSBoundParameters
        }
    }
}