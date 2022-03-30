function Get-FalconContainerToken {
<#
.SYNOPSIS
Retrieve your Falcon Container Security image registry token
.DESCRIPTION
Requires 'Falcon Container Image: Read'.
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Kubernetes-Protection
#>
    [CmdletBinding(DefaultParameterSetName='/container-security/entities/image-registry-credentials/v1:get')]
    param()
    process { Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName }
}