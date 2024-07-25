# CA Optics

Collection of hunting resources for gap identification in Conditonal Access Policies using CA Optics.


## Requirements

- [CAOptics](https://github.com/jsa2/caOptics)


## Instructions

### 1. Deploy CA Optics

```shell
docker run --rm -it -v $(pwd):/mnt/m1 node:14-bullseye bash
```
```shell
git clone https://github.com/jsa2/caOptics.git && cd caOptics && npm install
```

### 2. Authenticate to Microsoft Graph 

#### Alternative 1: using azure cli

```shell
curl -sL https://aka.ms/InstallAzureCLIDeb | bash
```

```shell
az login --use-device-code
```

#### Alternative 2: using a stolen access token

1. Ensure the token is issued for the `00000003-0000-0000-c000-000000000000` audience (i.e. Microsoft Graph)

2. Manually insert the token in `caoptics/tokenHandler/token.json` in the format `"<token>"`


### 3. Run CA Optics

```shell
node ./ca/main.js --mapping --clearPolicyCache
```

## Manually requesting an access token for Microsoft Graph

```shell
$body = @{
    "client_id" = "1950a258-227b-4e31-a9cf-717495945fc2"
    "scope" = "openid offline_access"
}
$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
$Headers=@{}
$Headers["User-Agent"] = $UserAgent
$authResponse = Invoke-RestMethod`
    -UseBasicParsing`
    -Method Post`
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode?api-version=1.0"`
    -Headers $Headers`
    -Body $body
$authResponse
```

```shell
$body=@{
    "client_id" = "1950a258-227b-4e31-a9cf-717495945fc2"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" = $authResponse.device_code
}
$Tokens = Invoke-RestMethod`
    -UseBasicParsing`
    -Method Post`
    -Uri "https://login.microsoftonline.com/Common/oauth2/v2.0/token?api-version=1.0"`
    -Headers $Headers`
    -Body $body
$Tokens.access_token
```
