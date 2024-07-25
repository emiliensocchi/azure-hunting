#### Description #################################################################################
#
# Provides an overview of all the Azure RBAC permissions assigned to the following security 
# principals in all subscriptions of an environment:
# • Users
# • Groups
# • Service principals and Managed Identities (both user-assigned and system-assigned)
#
# Note: Under 'Scope', '/' means that the scope for the role assignement is the Root management group
#
####

$armAccessToken = ""
Connect-AzAccount -AccessToken $armAccessToken -AccountId current

$path = "C:\Users\$env:UserName\Downloads\"
$file = "_IAM.txt" 
$date = (Get-Date -UFormat "%Y-%m-%d")
$resultFile = "${path}${date}${file}"
$finalOutputText = [System.Text.StringBuilder]::new()

if (!(test-path $path )) { New-Item -ItemType Directory -Force -Path $path }

$managedIdentityRegex = '^(https\:\/\/identity\.azure\.net).*'
$emptyIam = @'

DisplayName RoleDefinitionName Scope
----------- ------------------ -----
<none>


'@

$subscriptions = (Get-AzSubscription).Id | sort | Get-Unique

foreach ($subscription in $subscriptions) {
    Set-AzContext -Subscription $subscription
    
    $subscriptionName = (Get-AzSubscription -SubscriptionId $subscription).Name
    $userIam = (Get-AzRoleAssignment | where {$_.ObjectType -eq "User"} | select DisplayName, RoleDefinitionName, Scope | sort Scope | Format-Table -AutoSize | Out-String -Width 10000)
    $groupIam = (Get-AzRoleAssignment | where {$_.ObjectType -eq "Group"} | select DisplayName, RoleDefinitionName, Scope | sort Scope | Format-Table -AutoSize | Out-String -Width 10000)

    [void]$finalOutputText.AppendLine("================================================================")
    [void]$finalOutputText.AppendLine($subscriptionName)
    [void]$finalOutputText.AppendLine("================================================================")

    $outputText = "[User IAM]"
    Write-Output $outputText
    [void]$finalOutputText.AppendLine($outputText)

    if ($userIam) {
        Write-Output "$userIam"
        [void]$finalOutputText.AppendLine($userIam)

    } else {
        # No user has a role scoped to the current subscription
        Write-Output $emptyIam
        [void]$finalOutputText.AppendLine($emptyIam)
    }

	$outputText = "[Group IAM]"
    Write-Output "$outputText"
    [void]$finalOutputText.AppendLine($outputText)

    if ($groupIam) {
        Write-Output "$groupIam"
        [void]$finalOutputText.AppendLine($groupIam)

    } else {
        # No group has a role scoped to the current subscription
        Write-Output $emptyIam
        [void]$finalOutputText.AppendLine($emptyIam)
    }

    $userAssignedManagedIdentities = (Get-AzUserAssignedIdentity).PrincipalId
    $servicePrincipals = (Get-AzRoleAssignment | where {$_.ObjectType -eq "ServicePrincipal"} | select ObjectId, DisplayName, RoleDefinitionName, Scope)
    
    foreach ($servicePrincipal in $servicePrincipals) {
        $objectId = $servicePrincipal.ObjectId
        $servicePrincipalNames = (Get-AzADServicePrincipal -ObjectId $objectId).ServicePrincipalNames
        $isManagedIdentity = $false
        $isUserAssigned = $false

        foreach ($servicePrincipalName in $servicePrincipalNames) {
            if ($servicePrincipalName -match $managedIdentityRegex) {
                $isManagedIdentity = $true
                $isUserAssigned = if ($userAssignedManagedIdentities -ne $null -and $userAssignedManagedIdentities.Contains($objectId)) {$true} else {$false}
                break 
            }
        }

        if ($isManagedIdentity) {
            $i = [array]::IndexOf($servicePrincipals, $servicePrincipal)
            $displayName = $servicePrincipals[$i].DisplayName

            if ($isUserAssigned) {
                $servicePrincipals[$i].DisplayName = "$displayName (user-assigned MI)"
            } else {
                $servicePrincipals[$i].DisplayName = "$displayName (system-assigned MI)"
            }
        }
    }

    $servicePrincipalIam = ($servicePrincipals | select DisplayName, RoleDefinitionName, Scope | sort Scope | Format-Table -AutoSize | Out-String -Width 10000)

	$outputText = "[Service principal and Managed Identity IAM]"
    Write-Output "$outputText"
    [void]$finalOutputText.AppendLine($outputText)

    if ($servicePrincipalIam) {
        Write-Output "$servicePrincipalIam"
        [void]$finalOutputText.AppendLine($servicePrincipalIam)

    } else {
        # No service principal or Managed Identity has a role scoped to the current subscription
        Write-Output $emptyIam
        [void]$finalOutputText.AppendLine($emptyIam)
    }
}

Set-Content -Path $resultFile -Value $finalOutputText.toString()
Write-Output "Results successfully exported to: $resultFile"
