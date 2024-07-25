#### Description #################################################################################
#
# Indexes all the reply URLs containing 'azurewebsites.net' for all the App registrations in a tenant, and finds out those not pointing to any App Service.
# 
####

$tenantId = ""
$aadGraphAccessToken = ""
Connect-AzureAD -TenantId $tenantId -AadAccessToken $AadGraphAccessToken

$apps = Get-azureAdApplication -All $true
$urls = $apps | Where-Object {$_.ReplyUrls -match "azurewebsites.net"} | Select-Object -ExpandProperty replyurls | Where-Object {$_ -match "azurewebsites.net"}
 
$list = @()
foreach ($domain in $urls) {
    if ($domain -match "http://") {
        $list+=($domain -split "http://" -split "/")[1];
    }
 
    if ($domain -match "https://") {
        $list+=($domain -split "https://" -split "/")[1];
    }  
}
 
$results = @()
$ErrorActionPreference = "Stop"
foreach ($parsed in $list) {
    try {
       $s = Resolve-DnsName $parsed;
    }
        catch {
        Write-Host "Subdomain takeover possible for $parsed" -ForegroundColor red
        $ob =  $apps | where {$_.ReplyUrls -match $parsed}
        $ob | Add-Member -NotePropertyName "subdomain_takeOverPlausible" -NotePropertyValue $parsed -Force
        $results += $ob
    }   
}
 
$results | select -Unique subdomain_takeOverPlausible, *DisplayName*, appid
