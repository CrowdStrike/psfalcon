# Overview

[PSFalcon](https://github.com/crowdstrike/psfalcon) is a [PowerShell Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules?view=powershell-7) that lets CrowdStrike Falcon users interact with the CrowdStrike Falcon [OAuth2 APIs](https://assets.falcon.crowdstrike.com/support/api/swagger.html#/) without having extensive knowledge of APIs or PowerShell.

PSFalcon lets you automate tasks and perform actions in large numbers not normally accessible through the Falcon UI. For example, you could use PSFalcon to create scripts that:

* Modify large numbers of detections, incidents, policies or rules
* Utilize Real-time Response to perform an action on many devices at the same time
* Upload or download malware samples or Real-time Response files
* Create/modify configurations for MSSP parent and child environments

# Requirements
* An active Falcon subscription for the appropriate modules
* PowerShell 5.1+ (Windows), PowerShell 6+ (Linux/MacOS)
* A Falcon [OAuth2 API Client](https://falcon.crowdstrike.com/support/api-clients-and-keys) with appropriate roles

# Installation

## Install PowerShell

If not already present, install [PowerShell](https://github.com/PowerShell/PowerShell#get-powershell).

## Use the PowerShell Gallery
TODO

## Manual Installation using GitHub

If you're unable to use the PowerShell Gallery to install the module, you can download directly from GitHub.

1. Download the [master repository](https://github.com/CrowdStrike/psfalcon/archive/master.zip) as a ZIP.
2. Unpack the archive and move the contents of the `psfalcon-master` folder into your User Modules directory:

* Linux/MacOS
```powershell
$HOME/.local/share/powershell/Modules/PSFalcon/2.0.0
```

* Windows (PowerShell Core/6+)
```powershell
$HOME\Documents\PowerShell\Modules\PSFalcon\2.0.0
```

* Windows (PowerShell Desktop/5.1)
```powershell
$HOME\Documents\WindowsPowerShell\Modules\PSFalcon\2.0.0
```

## Importing the Module

The PSFalcon module must be loaded at the beginning of a PowerShell session or script in order to access the commands included with PSFalcon.

### PowerShell Session

**NOTE**: The `Import-Module` command can be added to your PowerShell `$PROFILE` to automatically load the module when you start PowerShell.

```powershell
Import-Module -Name PSFalcon
```

### PowerShell Script

```powershell
#Requires -Version 5.1 -Modules @{ModuleName='PSFalcon';ModuleVersion='2.0.0'}
```

## Folder Redirection

If you have “Folder Redirection” in place, the `$HOME` folder may not be properly recognized by PowerShell. In these cases, you can extract PSFalcon to a different folder and import the module directly from that folder when you want to use it.

For instance, if you unpacked it in a folder called "PSFalcon", you could navigate to the directory that folder is contained in and point `Import-Module` to the directory:

```powershell
Import-Module .\PSFalcon
```

# Commands and Example Usage
Please visit the **[PSFalcon Wiki](https://github.com/CrowdStrike/psfalcon/wiki)**.
