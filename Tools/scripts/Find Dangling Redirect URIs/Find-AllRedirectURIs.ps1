#### Description #################################################################################
#
# Indexes all the reply URLs containing 'azurewebsites.net' for all the App registrations in a tenant.
# Useful input for Aquatone and find out excessively exposed applications.
# 
####


$tenantId = ""
$aadGraphAccessToken = ""
Connect-AzureAD -TenantId $tenantId -AadAccessToken $AadGraphAccessToken

$path = "C:\Users\$env:UserName\Downloads\"
$file = "_dangling-redirectURIs.txt" 
$date = (Get-Date -UFormat "%Y-%m-%d")
$resultFile = "${path}${date}${file}"

if (!(test-path $path )) { New-Item -ItemType Directory -Force -Path $path }

$apps = Get-azureAdApplication -All $true
$urls = $apps | Where-Object {$_.ReplyUrls -match "azurewebsites.net"} | Select-Object -ExpandProperty replyurls | Where-Object {$_ -match "azurewebsites.net"}
 
$domains = @()
foreach ($domain in $urls) {
    if ($domain -match "http://") {
        $domains+=($domain -split "http://" -split "/")[1];
    }
 
    if ($domain -match "https://") {
        $domains+=($domain -split "https://" -split "/")[1];
    }  
}

Write-Output $domains
Write-Output ""
Write-Output ""

Set-Content -Path $resultFile -Value $domains
Write-Output "Results successfully exported to: $resultFile"
