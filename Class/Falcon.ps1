class Falcon {
    [string] $Hostname
    [string] $Id
    [string] $Secret
    [string] $CID
    [string] $Token
    [datetime] $Expires
    [array] $Endpoints
    [array] $Definitions
    Falcon ($Endpoints, $Definitions) {
        $this.Endpoints = $Endpoints
        $this.Definitions = $Definitions
        $this.psobject.typenames.insert(0,'Falcon')
    }
    [array] Endpoint($Endpoint) {
        return ($this.Endpoints | Where-Object { $Endpoint -contains $_.Name })
    }
    [string] Schema($Definition) {
        return ($this.Definitions | Where-Object { $_.Name -EQ $Definition })
    }
    [string] Rfc3339($Hours) {
        return "$([Xml.XmlConvert]::ToString((Get-Date).AddHours($Hours),[Xml.XmlDateTimeSerializationMode]::Utc))"
    }
}