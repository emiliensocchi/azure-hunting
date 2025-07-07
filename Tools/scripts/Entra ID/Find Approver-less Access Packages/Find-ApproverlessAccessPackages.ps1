#### Description ##############################################################################################################################
#
# Indexes all IGA Access Packages in a tenant and identifies those that do not require approval for access requests.
#
# Requirements:
#    An access token with the following claims:
#       - aud: https://elm.iga.azure.com
#       - scp: EntitlementManagement.Read.All
#
#####

# Pass-the-token authentication 
$igaToken  = ''

# Set output file location
$path = "C:\Users\$env:UserName\Downloads\"
$file = "_approverless_access-packages.csv" 
$date = (Get-Date -UFormat "%Y-%m-%d")
$resultFile = "${path}${date}${file}"

# Fetch all access packages
$packages = @()
$igaUri = "https://elm.iga.azure.com/api/v1/accessPackages"
$headers = @{
    "Authorization" = "Bearer $igaToken"
    "Content-Type"  = "application/json"
}

do {
    $response = Invoke-RestMethod -Uri $igaUri -Headers $headers -Method Get
    if ($response.value) {
        $packages += $response.value
    }
    $igaUri = $response.'@odata.nextLink'
} while ($igaUri)

# Filter access packages that do not require approval
$noApprovalPackages = @()
$n_packages = $packages.count
$processed_packages = 0

Write-Host "Total packages: $($n_packages)" -ForegroundColor Green

foreach ($package in $packages) {
    $progressPercent = [math]::Floor(($processed_packages / $n_packages) * 100)
    if ($progressPercent -in 25,50,75,100 -and ($processed_packages % [math]::Ceiling($n_packages * 0.25)) -eq 0) {
        Write-Host "Progress: $progressPercent% ($processed_packages/$n_packages)" -ForegroundColor Cyan
    }

    $approvalSettingsUri = "https://elm.iga.azure.com/api/v1/accessPackageAssignmentPolicies?`$filter=accessPackage/id eq '$($package.id)'"
    $policyResponse = Invoke-RestMethod -Uri $approvalSettingsUri -Headers $headers -Method Get

    foreach ($policy in $policyResponse.value) {
        if (-not $policy.requestApprovalSettings.isApprovalRequired -and $policy.requestorSettings.scopeType -ne "NoSubjects") {
            $noApprovalPackages += [PSCustomObject]@{
                packageId   = $package.id
                packageName = $package.displayName
                isPackageHidden = $package.isHidden
                packageDescription = $package.description
                policyId = $policy.id
                policyName = $policy.displayName
                policyScopeType = $policy.requestorSettings.scopeType 
                policyAllowedRequestors = ( $policy.requestorSettings.allowedRequestors | ForEach-Object { $_.description } ) -join ', '
                myAccessPortalLink = "https://myaccess.microsoft.com/@Storebrand.onmicrosoft.com#/access-packages/$($package.id)/"
            }
        }
    }
    $processed_packages++
}

# Export results
$noApprovalPackages | Select-Object * | Export-Csv -Path $resultFile -NoTypeInformation

Write-Host "Results exported to: $resultFile"
