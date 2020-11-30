@{
  Name = "intel/GetIntelActorEntities"
  Path = "/intel/entities/actors/v1"
  Method = "GET"
  Headers = @{
    Accept = "application/json"
  }
  Permission = "falconx-actors:read"
  Description = "List detailed information about Actors"
  Parameters = @(
    @{
      Dynamic = "ActorIds"
      Name = "ids"
      Type = "array"
      In = @( "query" )
      Required = $true
      Description = "The IDs of the actors you want to retrieve."
      Position = 1
    }
    @{
      Dynamic = "Fields"
      Name = "fields"
      Type = "array"
      In = @( "query" )
      Required = $false
      Description = "The fields to return or a predefined collection name surrounded by two underscores"
      Position = 2
    }
  )
  Responses = @{
    403 = "msa.ReplyMetaOnly"
    429 = "msa.ReplyMetaOnly"
    500 = "msa.ErrorsOnly"
    default = "domain.ActorsResponse"
  }
}