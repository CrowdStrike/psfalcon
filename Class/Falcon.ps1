class Falcon {
    [string] $Hostname
    [string] $Id
    [string] $Secret
    [string] $CID
    [string] $Token
    [datetime] $Expires
    [array] $Endpoints
    Falcon ($Endpoints) {
        $this.Endpoints = $Endpoints
        $this.PSObject.TypeNames.Insert(0,'Falcon')
    }
    [array] Endpoint($Endpoint) {
        return $this.Endpoints | Where-Object { $Endpoint -contains $_.Name }
    }
    [string] Response($Endpoint, $StatusCode) {
        if ($this.Endpoint($Endpoint).Responses.Keys -contains $StatusCode) {
            return $this.Endpoint($Endpoint).Responses.$StatusCode
        }
        else {
            return $this.Endpoint($Endpoint).Responses.default
        }
    }
    [string] Rfc3339($Hours) {
        return "$([Xml.XmlConvert]::ToString((Get-Date).AddHours($Hours),[Xml.XmlDateTimeSerializationMode]::Utc))"
    }
}