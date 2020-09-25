class Falcon {
    [string] $Hostname
    [string] $Id
    [securestring] $Secret
    [securestring] $Token
    [datetime] $Expires
    [string] $CID
    [array] $Endpoints

    Falcon ($Hostname) {
        # Set hostname
        $this.Hostname = $Hostname

        if (Test-Path "$this.cred") {
            # Import cached credentials
            $Cred = Import-Clixml "$this.cred"
            $this.Id = $Cred.UserName
            $this.Secret = $Cred.Password
        }
        if (Test-Path "$this.token") {
            # Import cached token
            $Import = Import-Clixml "$this.token"
        
            if ($Import.Expires -gt (Get-Date).AddSeconds(30)) {
                $this.Expires = $Import.Expires
                $this.Token = $Import.Token
            }
        }
        # Add PSTypeName
        $this.psobject.typenames.insert(0,'Falcon')
    }
    [array] Endpoint($Endpoint) {
        # Return endpoint detail
        return ($this.Endpoints | Where-Object { $Endpoint -contains $_.Name })
    }
    [string] ExportCred() {
        # Collect and export credentials
        $Cred = Get-Credential
        $this.Id = $Cred.UserName
        $this.Secret = $Cred.Password
        $Cred | Export-Clixml "$this.cred"
        return "Created $this.cred"
    }
    [string] ExportToken() {
        if ($this.Token -and $this.Expires) {
            # Save token for parallel processing tasks
            @{
                Expires = $this.Expires
                Token = $this.Token
            } | Export-Clixml "$this.token"
            return "Created $this.token"
        } else {
            return "No token available"
        }
    }
    [string] ImportCred($Name) {
        # Import credentials
        $Cred = Import-Clixml "$Name.cred"

        if ($Cred) {
            $this.Id = $Cred.UserName
            $this.Secret = $Cred.Password
            $this.Token = $null
            $this.Expires = Get-Date
            return "Imported $Name.cred"
        } else {
            return "$Name.cred does not exist"
        }
    }
    [string] Rfc3339($Days) {
        # Use XmlConvert to translate number of days into RFC-3339 timestamp
        return "$([Xml.XmlConvert]::ToString((Get-Date).AddDays($Days),[Xml.XmlDateTimeSerializationMode]::Utc))"
    }
}