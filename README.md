**WARNING**: The PSFalcon modules are an independent project and not supported by CrowdStrike.

# Requirements
Requires **[PowerShell 5.1+](https://github.com/PowerShell/PowerShell#get-powershell)**

# Installation
1. Download the files in this respository
2. Extract the archive into `PSFalcon` under one of your `$env:PSModulePath` directories

# Usage
You can list all available commands through `Get-Module -Name PSFalcon` once the module has
been imported. Using the `-Help` parameter with any command will show the available parameters and
a brief description.

# Credentials
In order to interact with the Falcon OAuth2 APIs, you need a valid **[API Client ID and Secret](https://falcon.crowdstrike.com/support/api-clients-and-keys)**.
If you have previously exported your credentials into `$Home\Falcon.cred`, they will be automatically imported
when you import the PSFalcon module from the `$Home` directory.

### Exporting Credentials
You can save your credentials using the `ExportCred()` method, which will prompt you for your ID (username)
and Secret (password). Once input, the credentials will be exported to `$Home\Falcon.cred`.

This exported file is designed to be used only by the user that created it, on the device that it was created on.
Attemping to copy this file to a different device or importing it into PSFalcon under a different user account
will fail. **[Learn more about encrypted credentials here](https://adamtheautomator.com/powershell-export-xml/#Saving_an_Encrypted_Credential)**.

```powershell
PS> $Falcon.ExportCred()
```
**WARNING**: This exported file is encrypted on Windows, but it is not encrypted on MacOS or Linux. Credential
handling in PSFalcon is provided for convenience and not security.

### Importing Credentials
You can rename these files to save different credential sets and import them using the `.ImportCred()`
method. When importing credentials you only need to specify the name of the file, as it will be imported from
the local path and default to using the `.cred` extension.

```powershell
PS> $Falcon.ImportCred('Example')
Imported Example.cred
```
**WARNING**: Once imported, you must request a new token before making requests inside of the new environment.

# Tokens
### Requesting Tokens
During a PowerShell session, you must have a valid OAuth2 token in order to make requests to the Falcon APIs.

If your credentials have already been loaded, PSFalcon will request a token on your behalf when you issue a
command. Otherwise, you must request a token and provide the credentials.

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
By default, token requests are sent to the US cloud. The `-Cloud` parameter can be used to choose a different
destination. Your choice is saved and all requests will be sent to the chosen cloud unless a new
`Request-FalconToken` request is made specifying a new cloud.

### Child Environments
If you're in an MSSP configuration, you can target specific child environments using the `-CID` parameter
during token requests. Your choice is saved and all requests will be sent to that particular
CID unless a new `Request-FalconToken` request is made specifying a new child environment.

### Exporting Tokens
You can export a token your have requested using the `.ExportToken()` method, which creates `$Home\Falcon.token`.
Once exported, this token will be automatically loaded with PSFalcon, which enables support for multi-threaded
PowerShell scripts. If the token has expired it will be ignored.