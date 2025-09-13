#Requires -Version 5.1
using module @{ModuleName='PSFalcon';ModuleVersion ='2.2'}
<#
.SYNOPSIS
Retrieve Security Assessment data for a configured domain in Falcon Identity Protection
.PARAMETER Domain
Configured domain name
.EXAMPLE
.\security-assessment-for-domain.ps1 -Domain example.com
#>
param(
  [Parameter(Mandatory,Position=1)]
  [ValidateScript({
    # Retrieve list of configured domains and compare against input
    [string[]]$List = try {
      (Invoke-FalconIdentityGraph -String '{domains(dataSources:[])}').domains
    } catch {
      throw "Unable to retrieve list of configured domains."
    }
    if (($List -contains $_)) { $true } else { throw "'$_' is not in the list of configured domains." }
  })]
  [string]$Domain
)
process {
  $String = "{securityAssessment(domain:" + ('"{0}"' -f $Domain) +
    '){overallScore,overallScoreLevel,assessmentFactors{riskFactorType,severity,likelihood}}}'
  try {
    foreach ($i in (Invoke-FalconIdentityGraph -String $String).securityAssessment) {
      foreach ($Factor in $i.assessmentFactors) {
        # For each assessmentFactor, return custom object with results that include domain and score
        [PSCustomObject]@{
          Domain = $Domain
          RiskFactorType = $Factor.riskFactorType
          Severity = $Factor.severity
          Likelihood = $Factor.likelihood
          OverallScore = $i.overallScore
          OverallScoreLevel = $i.overallScoreLevel
        }
      }
    }
  } catch {
    throw $_
  }
}