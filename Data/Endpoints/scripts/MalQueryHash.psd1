@{
  Name = "scripts/MalQueryHash"
  Description = "Perform a YARA-based MalQuery search for a specific hash"
  Permission = "malquery:write"
  Parameters = @(
    @{
      Dynamic = "Sha256"
      Type = "string"
      Pattern = "\w{64}"
      Required = $true
      Description = "SHA256 hash value"
      Position = 1
    }
  )
}