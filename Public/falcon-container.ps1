function Get-FalconContainerToken {
    [CmdletBinding(DefaultParameterSetName = '/container-security/entities/image-registry-credentials/v1:get')]
    param()
    process {
        Invoke-Falcon -Endpoint $PSCmdlet.ParameterSetName
    }
}