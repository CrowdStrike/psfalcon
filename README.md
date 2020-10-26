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

# Credentials
In order to interact with the Falcon OAuth2 APIs, you need a valid **[API Client ID and Secret](https://falcon.crowdstrike.com/support/api-clients-and-keys)**.

### Exporting Credentials
You can save your credentials using the `ExportCred()` method, which will prompt you for your Username (Id)
and Password (Secret). Once input, the credentials will be exported to `$pwd\Falcon.cred`. This file imports
from the local directory automatically when the PSFalcon module is loaded.

```powershell
PS> $Falcon.ExportCred()
```
**WARNING**: This exported file is encrypted on Windows, but not on MacOS or Linux. Credential handling in
PSFalcon is provided for convenience and not security. A password management system is recommended.

This exported file is designed to be used only by the user that created it, on the device that it was created on.
Attemping to copy this file to a different device or importing it into PSFalcon under a different user account
will fail. **[Learn more about encrypted credentials here](https://adamtheautomator.com/powershell-export-xml/#Saving_an_Encrypted_Credential)**.

### Importing Credentials
You can rename these files to save different credential sets and import them using the `.ImportCred()`
method. When importing credentials you only need to specify the name of the file, as it will be imported from
the local path and default to using the `.cred` extension.

```powershell
PS> $Falcon.ImportCred('Example')
Imported Example.cred
```

# Tokens

## Requesting Tokens
If your credentials have been loaded and you do not have a valid access token, PSFalcon will one on your behalf
when you issue a command. Otherwise, you must request a token and provide your credentials.

```powershell
PS> Request-FalconToken
Id: <string>
Secret: <SecureString>
```
**WARNING**: Using the optional `-Id` and `-Secret` parameters with `Request-FalconToken` will result in your
credentials being displayed in plain text. This could expose them to a third party.

Once a valid OAuth2 token is received, it is cached with your credentials. Your cached token will be checked
and refreshed as needed while running PSFalcon commands.

### Alternate Clouds
By default, token requests are sent to the 'us-1' cloud. The `-Cloud` parameter can be used for different
destinations. Your choice is saved and all requests will be sent to the chosen cloud unless a new
`Request-FalconToken` command is executed that specifies a new cloud.

### Child Environments
If you're using an MSSP configuration, you can target specific child environments using the `-CID` parameter
during token requests. Your choice is saved and all requests will be sent to that particular
CID unless a new `Request-FalconToken` command is executed that specifies a new environment.

### Exporting Tokens
You can export a token your have requested using the `.ExportToken()` method, which creates `$HOME\Falcon.token`.
Once exported, this token will be automatically loaded with PSFalcon, which enables support for multi-threaded
PowerShell scripts. If the token has expired it will be ignored.