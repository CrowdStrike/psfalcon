**WARNING**: The PSFalcon modules are an independent project and not supported by CrowdStrike.

# Requirements
Requires **[PowerShell 5.1](https://github.com/PowerShell/PowerShell#get-powershell)** or above.

# Installation
1. Download the files in this repository as a ZIP
2. Extract the archive
3. Move the contents of `psfalcon-master.zip` into your user modules directory:

Linux/MacOS (PowerShell Core):
```powershell
$HOME/.local/share/powershell/Modules/PSFalcon/2.0.0
```
Windows (PowerShell Core):
```powershell
$HOME\Documents\PowerShell\Modules\PSFalcon\2.0.0
```
Windows (PowerShell Desktop):
```powershell
$HOME\Documents\WindowsPowerShell\Modules\PSFalcon\2.0.0
```

# Usage
You can list available commands using `Get-Command -Module PSFalcon` once the module has been imported.

Because the parameters used by individual commands are dynamically loaded, the `Get-Help` PowerShell function
does not contain much information. Using the `-Help` parameter with any PSFalcon command will show the available
parameters and a brief description.

## Credentials
In order to interact with the Falcon OAuth2 APIs, you need a valid **[API Client ID and Secret](https://falcon.crowdstrike.com/support/api-clients-and-keys)**.

## Requesting Access Tokens
An access token is required in order to interact with the CrowdStrike OAuth2 APIs. If your credentials have
been loaded and you do not have a valid access token, PSFalcon will request one on your behalf when you issue
a command. You can also request a token and provide your credentials.

```powershell
PS> Request-FalconToken
Id: <string>
Secret: <string>
```

If your token request is successful, your token and credentials are cached. Your cached token will be checked
and refreshed as needed while running additional PSFalcon commands.

### Alternate Clouds
Requests are sent to the 'us-1' cloud by default. The `-Cloud` parameter can be used for different
destinations. Your choice is saved and all requests will be sent to the chosen cloud unless a new
`Request-FalconToken` command is executed that specifies a new cloud.

### Child Environments
If you're using an MSSP configuration, you can target child environments using the `-CID` parameter during an
initial token request. Your choice is saved and all requests will be sent to that particular CID unless a
new `Request-FalconToken` command is executed that specifies a new environment.