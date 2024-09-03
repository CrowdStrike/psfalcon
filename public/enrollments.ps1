function Invoke-FalconMobileAction {
<#
.SYNOPSIS
Trigger on-boarding process for a device in Falcon for Mobile
.DESCRIPTION
Requires 'Mobile Enrollment: Write'.
.PARAMETER Name
Action to perform
.PARAMETER EnrollmentType
Enrollment type
.PARAMETER ExpiresAt
Expiration time [default: 30 days]
.PARAMETER Email
Email address
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Invoke-FalconMobileAction
#>
  [CmdletBinding(DefaultParameterSetName='/enrollments/entities/details/v4:post',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/enrollments/entities/details/v4:post',Mandatory,Position=1)]
    [ValidateSet('enroll','re-enroll',IgnoreCase=$false)]
    [Alias('action_name')]
    [string]$Name,
    [Parameter(ParameterSetName='/enrollments/entities/details/v4:post',Position=2)]
    [Alias('enrollment_type')]
    [string]$EnrollmentType,
    [Parameter(ParameterSetName='/enrollments/entities/details/v4:post',Position=3)]
    [Alias('expires_at')]
    [string]$ExpiresAt,
    [Parameter(ParameterSetName='/enrollments/entities/details/v4:post',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=4)]
    [ValidateScript({
      if ((Test-RegexValue $_) -eq 'email') { $true } else { throw "'$_' is not a valid email address." }
    })]
    [Alias('email_addresses')]
    [string[]]$Email
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
    if (!$PSBoundParameters.ExpiresAt) { $PSBoundParameters.ExpiresAt = Convert-Rfc3339 720 }
  }
  process { if ($Email) { @($Email).foreach{ $List.Add($_) }}}
  end {
    if ($List) {
      $PSBoundParameters['Email'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}