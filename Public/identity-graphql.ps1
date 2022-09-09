function Invoke-FalconIdentityGraph {
    <#
        .SYNOPSIS
            Interact with the Falcon Identity Protection platform using GraphQ.

        .DESCRIPTION
            Invokes a provided query against the Falcon Identity Protection platform via GraphQL. 
            The Invoke-FalconIdentityGraph function is able to paginate through the results in its entirety.

            The API key permissions that are required in order to run this are:
                - Identity Protection Entities: Read
                - Identity Protection GraphQL: Write

        .PARAMETER Query
            GraphQL query statement. This parameter is mandatory

        .PARAMETER FalconCloud
            Specify the Falcon cloud you wish to query (US-1, US-2, EU-1, US-GOV-1). URLs for each instance:
                - US-1: https://api.crowdstrike.com
                - US-2: https://api.us-2.crowdstrike.com
                - EU-1: https://api.eu-1.crowdstrike.com
                - US-GOV-1: https://api.laggar.gcw.crowdstrike.com
            
                This parameter is mandatory.

        .EXAMPLE
            Query Falcon Identity to retieve all entities with the BuiltInAdministratorRole.

            PS> $query = '
                entities (   
                    # Query "Roles" to get administrator accounts:
                    roles: [BuiltinAdministratorRole]
                    # Sort the results in ascending primary display name order:
                    sortKey: PRIMARY_DISPLAY_NAME
                    sortOrder: ASCENDING
                )
                {
                    # Use "nodes" keyword when expecting multiple matching entities:
                    nodes {
                    # Requested fields:
                    primaryDisplayName
                    secondaryDisplayName
                    }
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
        
            .EXAMPLE
                Query Falcon Cloud US-2 for all user objects in Falcon Identity

                    $query = '
                        query ($after: Cursor)
                        {
                        entities(types: [USER]
                        archived: false
                        after: $after
                        first: 1000) {
                        nodes {
                                primaryDisplayName
                                secondaryDisplayName
                                riskScoreSeverity
                                hasADDomainAdminRole
                                riskFactors
                                {
                                    type
                                }
                                    accounts {
                                    description
                                    ... on ActiveDirectoryAccountDescriptor{
                                    passwordAttributes{
                                        lastChange
                                        strength
                                    }
                                    creationTime
                                    objectSid
                                    samAccountName
                                    domain
                                    enabled
                                    ou
                                    lastUpdateTime
                                    department
                                    servicePrincipalNames
                                    upn
                                    dn
                                    title
                                    userAccountControl
                                    objectGuid
                                    containingGroupEntities {
                                        secondaryDisplayName
                                    }
                                    flattenedContainingGroupEntities{
                                        secondaryDisplayName
                                    }
                                    }
                                }
                            }
                        pageInfo {
                            hasNextPage
                            endCursor
                        }
                        }
                        }'
                    
                    PS> Invoke-FalconIdentityGraph -FalconCloud US-2 -Query $query

                    Example Output: 
                        PrimaryDisplayName   : LIZ_ACOSTA
                        secondaryDisplayName : AFL.COM\LIZ_ACOSTA
                        riskScoreSeverity    : MEDIUM
                        hasADDomainAdminRole : False
                        riskFactors          : {@{type=STALE_ACCOUNT}, @{type=WEAK_PASSWORD_POLICY}}
                        accounts             : {@{description=Created with secframe.com/badblood.; passwordAttributes=; creationTime=10/14/2021 4:12:32 AM; objectSid=S-1-5-21-30036428-1354013063-3705842367-1952; samAccountName=LIZ_ACOSTA; domain=AFL.COM; 
                                            enabled=True; ou=AFL.com/Tier 1/BDE/Groups; lastUpdateTime=10/14/2021 4:12:32 AM; department=; servicePrincipalNames=System.Object[]; upn=LIZ_ACOSTA@AFL.com; dn=CN=LIZ_ACOSTA,OU=Groups,OU=BDE,OU=Tier 
                                            1,DC=AFL,DC=com; title=; userAccountControl=512; objectGuid=48f58645-fb49-4724-aa86-807149a41ec3; containingGroupEntities=System.Object[]; flattenedContainingGroupEntities=System.Object[]}}

                        primaryDisplayName   : DARIUS_HUNTER
                        secondaryDisplayName : AFL.COM\DARIUS_HUNTER
                        riskScoreSeverity    : MEDIUM
                        hasADDomainAdminRole : False
                        riskFactors          : {@{type=STALE_ACCOUNT}, @{type=WEAK_PASSWORD_POLICY}}
                        accounts             : {@{description=Created with secframe.com/badblood.; passwordAttributes=; creationTime=10/14/2021 4:11:40 AM; objectSid=S-1-5-21-30036428-1354013063-3705842367-1615; samAccountName=DARIUS_HUNTER; domain=AFL.COM; 
                                            enabled=True; ou=AFL.com/Tier 2/FSR/Devices; lastUpdateTime=10/14/2021 4:11:40 AM; department=; servicePrincipalNames=System.Object[]; upn=DARIUS_HUNTER@AFL.com; dn=CN=DARIUS_HUNTER,OU=Devices,OU=FSR,OU=Tier 
                                            2,DC=AFL,DC=com; title=; userAccountControl=512; objectGuid=48fe10c2-7672-416f-a18b-38106db6a8e1; containingGroupEntities=System.Object[]; flattenedContainingGroupEntities=System.Object[]}}

                        primaryDisplayName   : ANDERSON_SYKES
                        secondaryDisplayName : AFL.COM\ANDERSON_SYKES
                        riskScoreSeverity    : MEDIUM
                        hasADDomainAdminRole : False
                        riskFactors          : {@{type=STALE_ACCOUNT}, @{type=WEAK_PASSWORD_POLICY}}
                        accounts             : {@{description=Created with secframe.com/badblood.; passwordAttributes=; creationTime=10/14/2021 4:12:39 AM; objectSid=S-1-5-21-30036428-1354013063-3705842367-1997; samAccountName=ANDERSON_SYKES; 
                                            domain=AFL.COM; enabled=True; ou=AFL.com/Admin/Tier 2/T2-Servers; lastUpdateTime=10/14/2021 4:12:39 AM; department=; servicePrincipalNames=System.Object[]; upn=ANDERSON_SYKES@AFL.com; 
                                            dn=CN=ANDERSON_SYKES,OU=T2-Servers,OU=Tier 2,OU=Admin,DC=AFL,DC=com; title=; userAccountControl=512; objectGuid=490652ce-f3bc-405f-972b-170043460a4b; containingGroupEntities=System.Object[]; 
                                            flattenedContainingGroupEntities=System.Object[]}}

    #>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateSet('US-1','US-2','EU-1','US-GOV-1')]
        [string]$FalconCloud,
        [Parameter (Mandatory=$true)]
        [string]$Query
    )

    begin
    {
        if (!$Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization -or !$Script:Falcon.Hostname) 
        {

            # Request initial authorization token if one doesnt exist already
            Request-FalconToken
            
        }

        switch ($FalconCloud) 
        {
            'US-1' 
            {

                $GraphURL = "https://api.crowdstrike.com/identity-protection/combined/graphql/v1"

            }

            'US-2'
            {

                $GraphURL = "https://api.us-2.crowdstrike.com/identity-protection/combined/graphql/v1"

            }

            'EU-1'
            {

                $GraphURL = "https://api.eu-1.crowdstrike.com/identity-protection/combined/graphql/v1"

            }

            'US-GOV-1'
            {

                $GraphURL = "https://api.laggar.gcw.crowdstrike.com/identity-protection/combined/graphql/v1"

            }

            Default
            {
                # US-1 as default
                $GraphURL = "https://api.crowdstrike.com/identity-protection/combined/graphql/v1"
                
            }

        }

    } 
    
    process
    {
        $params = @{
            Uri         = $GraphURL
            Headers     = @{ 'Authorization' = $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization }
            Method      = 'POST'
            Body 		= @{"query"=$Query} | ConvertTo-Json		
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }


        $Request = Invoke-RestMethod @params
        $Results = $Request.data.entities.nodes
        $ResultsPageInfo = $Request.data.entities.pageInfo

        if (!$ResultsPageInfo)
        {

            Write-Verbose "No pageInfo was returned from the provided graph query. Will be unable to paginate if more results are available."

        }

        else
        {

            $EndCursor = $ResultsPageInfo.endCursor
            if ($RequestPageInfo.hasNextPage -eq $true)
            {

                $pageTracker = $true

                while ($pageTracker -eq $true)
                {

                    $Query = ($Query.Replace('($after: Cursor)','')).Replace('$after',"$endCursor")
                    $sessionVariables = @{after = $EndCursor} 

                    $params = @{
                        Uri             = $GraphURL
                        Headers         = @{ 'Authorization' = $Script:Falcon.Api.Client.DefaultRequestHeaders.Authorization }
                        Method          = 'POST'
                        Body 		    = @{"query"=$Query} | ConvertTo-Json		
                        ContentType     = 'application/json'
                        SessionVariable = $sessionVariables
                        ErrorAction     = 'Stop'
                    }

                    $Request = Invoke-RestMethod @params
                    $Results = $Results + $Request.data.entities.nodes
                    $ResultsPageInfo = $Request.data.entities.pageInfo
                    $EndCursor = $ResultsPageInfo.endCursor

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

        
    }

    end
    {

        Write-Output $Results

    }

}