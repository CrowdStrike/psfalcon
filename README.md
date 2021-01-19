# Overview

[PSFalcon](https://github.com/crowdstrike/psfalcon) is a [PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules?view=powershell-7) that lets CrowdStrike Falcon users interact with the CrowdStrike Falcon [OAuth2 APIs](https://assets.falcon.crowdstrike.com/support/api/swagger.html#/) without having extensive knowledge of APIs or PowerShell.

PSFalcon lets you automate tasks and perform actions in large numbers not normally accessible through the Falcon UI. For example, you could use PSFalcon to create scripts that:

* Modify large numbers of detections, incidents, policies or rules
* Utilize Real-time Response to perform an action on many devices at the same time
* Upload or download malware samples or Real-time Response files
* Create/modify configurations for MSSP parent and child environments

### _**Visit the [PSFalcon Wiki](https://github.com/CrowdStrike/psfalcon/wiki).**_

# Requirements
* An active Falcon subscription for the appropriate modules
* PowerShell 5.1+ (Windows), PowerShell 6+ (Linux/MacOS)
* A Falcon [OAuth2 API Client](https://falcon.crowdstrike.com/support/api-clients-and-keys) with appropriate roles
