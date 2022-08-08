function Invoke-FalconIdentityGraph {
    <#
        .SYNOPSIS
            Interact with the Falcon Identity Protection platform using GraphQL

        .DESCRIPTION
            Invokes a provided query against the Falcon Identity Protection platform via GraphQL. 
            The Invoke-FalconIdentityGraph function is able to paginate through the results in its entirety

            The API key permissions that are required in order to run this are:
                - Identity Protection Entities: Read
                - Identity Protection GraphQL: Write

        .PARAMETER Query
            GraphQL query statement

        .EXAMPLE
            Query Falcon Identity to retieve all entities with the BuiltInAdministratorRole

            PS> $query = '
                    Query:
                    entities (
                        # Returns all entities that hold the built in administrators role
                        roles: [BuiltinAdministratorRole]
                        sortKey: PRIMARY_DISPLAY_NAME
                        sortOrder: ASCENDING
                        first: 1000
                    )
                    {
                        nodes {
                        primaryDisplayName
                        secondaryDisplayName
                        }
                        pageInfo {
                        hasNextPage
                        endCursor
                        }
                    }'
            
            PS> Invoke-FalconIdentityGraph -Query $query


            Example output:
            {
                "data": {
                    "Query": {
                    "nodes": [
                        {
                        "primaryDisplayName": "Administrator",
                        "secondaryDisplayName": "XYZ.COM\\Administrator"
                        },
                        {
                        "primaryDisplayName": "Administrator",
                        "secondaryDisplayName": "UIC.COM\\Administrator"
                        },
                        {
                        "primaryDisplayName": "Administrator",
                        "secondaryDisplayName": "JTO.COM\\Administrator"
                        },
                        {
                        "primaryDisplayName": "Administrator",
                        "secondaryDisplayName": "SKO.COM\\Administrator"
                        },
                        {
                        "primaryDisplayName": "Administrator",
                        "secondaryDisplayName": "GNA.COM\\Administrator"
                        }
                    ],
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": "eyJwcmltYXJ5RGlzcGxhnzION892iJBZG1pbmlzdHJhdG9yIiwiX2lkIjoiMTVjYTFjMDYtZjRiZC00ZmU5LTkzOTItMGE0YzhmOTI3OWRiIn0="
                    }
                    }
                },
                "extensions": {
                    "runTime": 38,
                    "remainingPoints": 499995,
                    "reset": 9998,
                    "consumedPoints": 5
                }
            }

    #>

    [CmdletBinding(DefaultParameterSetName='/identity-protection/combined/graphql/v1:post',SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName='/identity-protection/combined/graphql/v1:post',Mandatory,ValueFromPipeline,
            ValueFromPipelineByPropertyName,Position=1)]
        [string]$Query
    )

    begin 
    {

        $Param = @{
            Command = $MyInvocation.MyCommand.Name
            Endpoint = $PSCmdlet.ParameterSetName
            Format = @{Body = @{ root = @('query') }}
        }

    }

    process 
    {
        
        $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters 
        $Results = $Request.entities.nodes
        $RequestPageInfo = $Request.entities.pageInfo
        $EndCursor = $RequestPageInfo.endCursor

        if ($RequestPageInfo.hasNextPage -eq $true)
        {

            $pageTracker = $true

            while ($pageTracker -eq $true)
            {

                $query = ($query.Replace('($after: Cursor)','')).Replace('$after',"$endCursor")
                $sessionVariables = @{after = $EndCursor} 

                $Param = @{
                    Command = $MyInvocation.MyCommand.Name
                    Endpoint = $PSCmdlet.ParameterSetName
                    Format = @{ 
                        Body = @{ root = @('query') }
                        SessionVariable = $sessionVariables
                    }
                }

                $Request = Invoke-Falcon @Param -Inputs $PSBoundParameters 
                $Results = $Results + $Request.data.entities.nodes
                $RequestPageInfo = $Request.data.entities.pageInfo
                $EndCursor = $RequestPageInfo.endCursor

                if ($ResultsPageInfo.hasNextPage -eq $true)
                {

                    $pageTracker = $true

                }

                else
                {

                    $pageTracker = $false

                }

            }

        }

    }

    end
    {

        Write-Output $Results

    }

}