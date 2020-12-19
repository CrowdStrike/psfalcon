@{
  Name = "scripts/ShowMap"
  Path = "/intelligence/graph?indicators="
  Method = "POST"
  Description = "Graph Indicators"
  Parameters = @(
    @{
      Dynamic = "Indicators"
      Type = "array"
      In = @( "query" )
      Required = $true
      Pattern = "(sha256|md5|domain|ipv4|ipv6):.*"
      Description = "Indicators to graph"
    }
  )
}