#### Description ##############################################################################################################################
#
# Verifies whether multi-tenant non-Microsoft service principals are locking the creation of new password and key credentials (certificates) 
# to prevent their compromise (refered to as "Credentials used for verification" in App Instance Property lock).
#
# More info: 
#    https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-app-instance-property-locks
# 
# Requirements:
#    An access token with the following MS Graph permissions (as application or delegated permissions):
#       - Application.ReadWrite.All 
#       - Directory.Read.All
#
# Warning:
#   For some unknow reason, removing the certificate uploaded to test the 'keyCredentials' property sometimes fail.
#   Note that uploaded certificates are set to expire after 1 minute.
#
####


### FUNCTIONS #######################################################
function Get-ProofOfPossession {
    <#
        Generates a proof of possession of the passed PFX certificate issued by the passed service principal.

        Args:
            $servicePrincipalId (String): the Id of the service principal to be used as issuer
            $pfxLocation (String): the location of the PFX certificate used to sign the proof of possession

        Returns:
            String: a proof of possession in the form of a JWT token
    #>
    param (
        [string]$servicePrincipalId,
        [string]$pfxLocation
    )
    # Load the the passed PFX certificate
    $securePassword = ConvertTo-SecureString -String "dummy" -Force -AsPlainText
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxLocation, $securePassword)
    $certificateB64Hash = [System.Convert]::ToBase64String($certificate.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '='

    # Create JWT header
    $header = @{
        alg = "RS256"
        typ = "JWT"
        x5t = $certificateB64Hash
    }

    # Create JWT payload
    $payload = @{
        aud = "00000002-0000-0000-c000-000000000000"
        iss = $servicePrincipalId
        nbf = [System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        exp = [System.DateTimeOffset]::UtcNow.AddMinutes(10).ToUnixTimeSeconds()
    }
    
    # Remove padding and construct unsigned JWT
    $headerByte = [System.Text.Encoding]::UTF8.GetBytes(($header | ConvertTo-Json))
    $payloadByte = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json))
    $headerBase64 = [System.Convert]::ToBase64String($headerByte) -replace '='
    $claimsBase64 =[System.Convert]::ToBase64String($payloadByte) -replace '='
    $unsignedToken = "$headerBase64.$claimsBase64"

    # Sign the JWT
    $hashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
    $rsaPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    $b64UrlSignature = [System.Convert]::ToBase64String($privateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($unsignedToken), $hashAlgorithm, $rsaPadding)) -replace '\+', '-' -replace '/', '_' -replace '='
    $jwt = "$unsignedToken.$b64UrlSignature"

    return $jwt
}


### MAIN ###########################################################

# Dummy certificate files
$certificateLocation = "$PSScriptRoot\dummy.cer"    # dummy certificate valid for 100 years
$pfxLocation = "$PSScriptRoot\dummy.pfx"            # pfx file for the dummy certificate

# Authentication
# Interactive delegated authentication
#Connect-MgGraph -Scopes "Application.ReadWrite.All", "Directory.Read.All"

# Pass-the-token authentication
$msgraphToken  = ''
$secureToken = ConvertTo-SecureString -String $msgraphToken -AsPlainText -Force 
Connect-MgGraph -NoWelcome -AccessToken $secureToken 

# Testing SPs
$tenantId = (Get-MgOrganization).Id
$microsoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
$multiTenantAudience = 'AzureADMultipleOrgs'
$allServicePrincipals = Get-MgServicePrincipal -All
$testedMultiTenantServicePrincipals = @()

foreach ($servicePrincipal in $allServicePrincipals) {
    $appOwnerOrganizationId = $servicePrincipal.AppOwnerOrganizationId
    $signInAudience = $servicePrincipal.SignInAudience

    if (($AppOwnerOrganizationId -ne $microsoftTenantId) -And ($AppOwnerOrganizationId -ne $tenantId) -And ($signInAudience -eq $multiTenantAudience)) {
        # The SP belongs to a non-Microsoft multi-tenant App, registered in a different tenant than the current one
        $servicePrincipalId = $servicePrincipal.Id
        $servicePrincipalName = $servicePrincipal.DisplayName
        $testedServicePrincipal = [PSCustomObject]@{
            ObjectId = $servicePrincipalId
            DisplayName = $servicePrincipalName
            IsPasswordCredsLocked = $false
            IsKeyCredsLocked = $false
        }

        ## Testing the 'passwordCredentials' property
        try {
            $passwordCredential = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphPasswordCredential
            $passwordCredential.DisplayName = 'Locked down passwordCredentials?'
            $passwordCredential.EndDateTime = (Get-Date).AddMinutes(1)
            $passwordCredential.StartDateTime = Get-Date
            $credential = Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipalId -PasswordCredential $passwordCredential

            if ($credential) {
                # The 'passwordCredentials' property of the SP is not protected
                $testedServicePrincipal.IsPasswordCredsLocked = $false
                Remove-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipalId -KeyId $credential.KeyId
            }
        } catch {
            $defaultInstancePropertyLockError = 'CannotUpdateLockedServicePrincipalProperty'
            $errorRecord = $_
            $errorCode = $errorRecord.Exception.ErrorCode

            if ($errorCode -eq $defaultInstancePropertyLockError) {
                # The 'passwordCredentials' property of the SP is protected as expected
                $testedServicePrincipal.IsPasswordCredsLocked = $true

            } else {
                Write-Host "An error occurred: $errorRecord"
            }
        }

        ## Testing the 'keyCredentials' property (certificate)
        try {
            $keyCredential = New-Object -TypeName Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential
            $keyCredential.DisplayName = 'Locked down keyCredentials?'
            $keyCredential.EndDateTime = (Get-Date).AddMinutes(1)
            $keyCredential.StartDateTime = Get-Date
            $keyCredential.Type = 'AsymmetricX509Cert'
            $keyCredential.Usage = 'Verify'
            
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificateLocation)
            $keyCredential.Key = [System.Convert]::FromBase64String([System.Convert]::ToBase64String($certificate.RawData))

            Update-MgServicePrincipal -ServicePrincipalId $servicePrincipalId -KeyCredential @($keyCredential)

            if ($credential) {
                # The 'keyCredentials' property of the SP is not protected
                $testedServicePrincipal.IsKeyCredsLocked = $false
                $proofOfPossession = Get-ProofOfPossession -servicePrincipalId $servicePrincipalId -pfxLocation $pfxLocation
                Remove-MgServicePrincipalKey -ServicePrincipalId $servicePrincipalId -KeyId $credential.KeyId -Proof $proofOfPossession
            }
        } catch {
            $defaultInstancePropertyLockError = 'Request_BadRequest'
            $errorRecord = $_
            $errorCode = $errorRecord.Exception.ErrorCode

            if ($errorCode -eq $defaultInstancePropertyLockError) {
                # The 'keyCredentials' property of the SP is protected as expected
                $testedServicePrincipal.IsKeyCredsLocked = $true   
                
            } else {
                Write-Host "An error occurred: $errorRecord"
            }
        }

        $testedMultiTenantServicePrincipals += $testedServicePrincipal
    }
}

$testedMultiTenantServicePrincipals | Format-Table -AutoSize
