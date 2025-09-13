function Get-FalconCloudAsset {
<#
.SYNOPSIS
Search for Falcon Cloud Security assets
.DESCRIPTION
Requires 'Cloud Security API Assets: Read'.
.PARAMETER Id
Asset identifier
.PARAMETER Filter
Falcon Query Language expression to limit results
.PARAMETER Sort
Property and direction to sort results
.PARAMETER Limit
Maximum number of results per request [default: 500]
.PARAMETER Offset
Position to begin retrieving results
.PARAMETER After
Pagination token to retrieve the next set of results
.PARAMETER Detailed
Retrieve detailed information
.PARAMETER All
Repeat requests until all available results are retrieved
.PARAMETER Total
Display total result count instead of results
.LINK
https://github.com/crowdstrike/psfalcon/wiki/Get-FalconCloudAsset
#>
  [CmdletBinding(DefaultParameterSetName='/cloud-security-assets/queries/resources/v1:get',SupportsShouldProcess)]
  param(
    [Parameter(ParameterSetName='/cloud-security-assets/entities/resources/v1:get',Mandatory,
      ValueFromPipelineByPropertyName,ValueFromPipeline,Position=1)]
    [Alias('ids')]
    [string[]]$Id,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get',Position=1)]
    [ValidateScript({Test-FqlStatement $_})]
    [string]$Filter,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get',Position=2)]
    [ValidateSet('account_id|asc','account_id|desc','account_name|asc','account_name|desc','active|asc',
      'active|desc','cloud_provider|asc','cloud_provider|desc','cluster_id|asc','cluster_id|desc',
      'cluster_name|asc','cluster_name|desc','creation_time|asc','creation_time|desc',
      'data_classifications.found|asc','data_classifications.found|desc','data_classifications.scanned|asc',
      'data_classifications.scanned|desc','first_seen|asc','first_seen|desc','id|asc','id|desc','instance_id|asc',
      'instance_id|desc','instance_state|asc','instance_state|desc','ioa_count|asc','ioa_count|desc',
      'iom_count|asc','iom_count|desc','managed_by|asc','managed_by|desc','organization_Id|asc',
      'organization_Id|desc','os_version|asc','os_version|desc','platform_name|asc','platform_name|desc',
      'publicly_exposed|asc','publicly_exposed|desc','region|asc','region|desc','resource_id|asc',
      'resource_id|desc','resource_name|asc','resource_name|desc','resource_type|asc','resource_type|desc',
      'resource_type_name|asc','resource_type_name|desc','service|asc','service|desc','ssm_managed|asc',
      'ssm_managed|desc','status|asc','status|desc','tenant_id|asc','tenant_id|desc','updated_at|asc',
      'updated_at|desc','vmware.guest_os_id|asc','vmware.guest_os_id|desc','vmware.guest_os_version|asc',
      'vmware.guest_os_version|desc','vmware.host_system_name|asc','vmware.host_system_name|desc',
      'vmware.host_type|asc','vmware.host_type|desc','vmware.instance_uuid|asc','vmware.instance_uuid|desc',
      'vmware.vm_host_name|asc','vmware.vm_host_name|desc','vmware.vm_tools_status|asc',
      'vmware.vm_tools_status|desc','zone|asc','zone|desc',IgnoreCase=$false)]
    [string]$Sort,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get',Position=3)]
    [ValidateRange(1,1000)]
    [int32]$Limit,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get')]
    [string]$Offset,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get')]
    [string]$After,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get')]
    [switch]$Detailed,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get')]
    [switch]$All,
    [Parameter(ParameterSetName='/cloud-security-assets/queries/resources/v1:get')]
    [switch]$Total
  )
  begin {
    $Param = @{ Command = $MyInvocation.MyCommand.Name; Endpoint = $PSCmdlet.ParameterSetName }
    [System.Collections.Generic.List[string]]$List = @()
  }
  process {
    if ($Id) { @($Id).foreach{ $List.Add($_) }} else { Invoke-Falcon @Param -UserInput $PSBoundParameters }
  }
  end {
    if ($List) {
      $Param['Max'] = 100
      $PSBoundParameters['Id'] = @($List)
      Invoke-Falcon @Param -UserInput $PSBoundParameters
    }
  }
}