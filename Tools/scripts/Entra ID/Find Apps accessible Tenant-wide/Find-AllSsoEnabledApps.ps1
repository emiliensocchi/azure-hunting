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


# Get Service Principals that are configured with SSO
$servicePrincipals = Get-MgBetaServicePrincipal -All

$ssoEnabledApps = $servicePrincipals | Where-Object {
    -not ([string]::IsNullOrEmpty($_.PreferredSingleSignOnMode))
}

# Helper function to get assigned users and groups for a service principal using the Beta API
function Get-AssignedPrincipals {
    param($spId)
    $assignments = Get-MgBetaServicePrincipalAppRoleAssignedTo -ServicePrincipalId $spId -All
    if (-not $assignments) { return "" }

    $lines = @()
    foreach ($assignment in $assignments) {
        $principalId = $assignment.PrincipalId
        $principalDisplayName = $assignment.PrincipalDisplayName
        $principalType = $assignment.PrincipalType
        $lines += ("[{0}] {1} ({2})" -f $principalType, $principalDisplayName, $principalId)
    }
    return ($lines -join "`n")
}

# Export results with assigned users/groups
$ssoEnabledApps | Select-Object DisplayName, AppId, PreferredSingleSignOnMode, AppRoleAssignmentRequired, 
    @{Name="AssignedUsersAndGroups";Expression={ Get-AssignedPrincipals $_.Id }},
    @{Name="MyAppsUri (SSO)";Expression={"https://launcher.myapps.microsoft.com/api/signin/$($_.AppId)?tenantId=$tenantId"}} |
Export-Csv -Path $resultFile -NoTypeInformation

Write-Host "Results exported to: $resultFile"
