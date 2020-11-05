class Falcon {
    [string] $Hostname
    [string] $Id
    [string] $Secret
    [string] $CID
    [string] $Token
    [datetime] $Expires
    [array] $Endpoints

    Falcon ($Hostname, $Endpoints) {
        $this.Hostname = $Hostname
        $this.Endpoints = $Endpoints
        $this.psobject.typenames.insert(0,'Falcon')
    }
    [array] Endpoint($Endpoint) {
        return ($this.Endpoints | Where-Object { $Endpoint -contains $_.Name })
    }
    [string] Rfc3339($Hours) {
        return "$([Xml.XmlConvert]::ToString((Get-Date).AddHours($Hours),[Xml.XmlDateTimeSerializationMode]::Utc))"
    }
}