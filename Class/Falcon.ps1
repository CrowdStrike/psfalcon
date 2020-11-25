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
        return $this.Endpoints | Where-Object { $Endpoint -contains $_.Name }
    }
    [array] Definition($Definition) {
        return ($this.Definitions | Where-Object { $_.Name -EQ $Definition }).Fields
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