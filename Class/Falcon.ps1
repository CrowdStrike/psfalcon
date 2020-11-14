class Falcon {
    [string] $Hostname
    [string] $Id
    [string] $Secret
    [string] $CID
    [string] $Token
    [datetime] $Expires
    [array] $Endpoints
    [array] $Responses
    Falcon ($Endpoints, $Responses) {
        $this.Endpoints = $Endpoints
        $this.Responses = $Responses
        $this.psobject.typenames.insert(0,'Falcon')
    }
    [array] Endpoint($Endpoint) {
        return ($this.Endpoints | Where-Object { $Endpoint -contains $_.Name })
    }
    [string] Response($Response) {
        return ($this.Responses | Where-Object { $_.Name -EQ $Response })
    }
    [string] Rfc3339($Hours) {
        return "$([Xml.XmlConvert]::ToString((Get-Date).AddHours($Hours),[Xml.XmlDateTimeSerializationMode]::Utc))"
    }
}