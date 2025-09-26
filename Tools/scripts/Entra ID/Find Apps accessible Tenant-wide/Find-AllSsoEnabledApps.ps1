#### Description ##############################################################################################################################
#
# Indexes all SSO-enabled applications in an Entra tenant, displays whether they require app role assignments, 
# and their assigned users and groups when applicable.
#
# Requirements:
#    An access token with the following MS Graph permissions (as application or delegated permissions):
#       - Application.Read.All 
#
#####

Import-Module Microsoft.Graph.Beta.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Beta.Users -ErrorAction Stop
Import-Module Microsoft.Graph.Beta.Groups -ErrorAction Stop

# Pass-the-token authentication
$msgraphToken  = '_VALID-ACCESS-TOKEN-FOR_MS-GRAPH_'
$secureToken = ConvertTo-SecureString -String $msgraphToken -AsPlainText -Force 
Connect-MgGraph -NoWelcome -AccessToken $secureToken -ErrorAction Stop 

# Retrieve tenant Id
$tenantId = (Get-MgBetaOrganization).Id

# Set output file location
$path = "C:\Users\$env:UserName\Downloads\"
$file = "_sso-enabled-apps.csv" 
$date = (Get-Date -UFormat "%Y-%m-%d")
$resultFile = "${path}${date}${file}"

# Helper function to get assigned users and groups for a service principal using the Beta API
function Get-AssignedPrincipals {
    param($spId)
    $assignments = Get-MgBetaServicePrincipalAppRoleAssignedTo -ServicePrincipalId $spId -All
    if (-not $assignments) { return "" }

    Write-Host "Found $($assignments.Count) assignments for Service Principal ID: $spId"
    $lines = @()
    foreach ($assignment in $assignments) {
        $principalId = $assignment.PrincipalId
        $principalDisplayName = $assignment.PrincipalDisplayName
        $principalType = $assignment.PrincipalType
        $lines += ("[{0}] {1} ({2})" -f $principalType, $principalDisplayName, $principalId)
    }
    return ($lines -join "`n")
}

# Helper function to get reply URIs (redirect URIs) for a service principal
function Get-ReplyUris {
    param($sp)
    if ($sp.ReplyUrls -and $sp.ReplyUrls.Count -gt 0) {
        return ($sp.ReplyUrls -join "`n")
    } elseif ($sp.Web -and $sp.Web.RedirectUris -and $sp.Web.RedirectUris.Count -gt 0) {
        return ($sp.Web.RedirectUris -join "`n")
    } else {
        return ""
    }
}

# Get all Service Principals using manual paging
$servicePrincipals = @()
$page = Get-MgBetaServicePrincipal -Top 999
while ($page) {
    $servicePrincipals += $page
    $nextLink = $page.'@odata.nextLink'
    if ($nextLink) {
        $page = Invoke-MgGraphRequest -Uri $nextLink
        # Convert result to the same type as Get-MgBetaServicePrincipal output
        if ($page.value) { $page = $page.value } else { $page = @() }
    } else {
        $page = $null
    }
}

# Exclude Service Principals published by Microsoft
$filteredServicePrincipals = $servicePrincipals | Where-Object {
    -not ($_.Publisher -match '.*Microsoft.*')
}

# Export results with assigned users/groups and reply URIs
$filteredServicePrincipals | Select-Object DisplayName, AppId, PreferredSingleSignOnMode, AppRoleAssignmentRequired, 
    @{Name="AssignedUsersAndGroups";Expression={ Get-AssignedPrincipals $_.Id }},
    @{Name="ReplyUris";Expression={ Get-ReplyUris $_ }},
    @{Name="MyAppsUri (SSO)";Expression={"https://launcher.myapps.microsoft.com/api/signin/$($_.AppId)?tenantId=$tenantId"}} |
Export-Csv -Path $resultFile -NoTypeInformation

Write-Host "Results exported to: $resultFile"
