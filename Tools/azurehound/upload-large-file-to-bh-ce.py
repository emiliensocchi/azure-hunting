"""
    Import large files to BloodHound CE (over 1 GB) using BloodHound's API.

    Credits:
        https://gist.github.com/aconite33/37c23b24e71180750d0ab0c4679507fd

"""
import requests
import json
import time
import argparse
import getpass
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Command line upload of large files into BloodHound CE edition")
    parser.add_argument('-f', '--file', type=str, help="File of JSON you want to upload.", required=True)
    parser.add_argument('-u', '--user', type=str, help="Username to login with.", required=True)


    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            sys.exit("File path doesn't exist.")

    if args.user:
        password = getpass.getpass(f"Enter password for {args.user}:")

    print("Logging in...")

    loginPayload = {
            "login_method": "secret",
            "secret": password,
            "username": args.user
            }

    response = requests.post('http://localhost:8080/api/v2/login', json=loginPayload)
    response_content = response.content.decode('utf-8')
    json_obj = json.loads(response_content)
    session_token = json_obj['data']['session_token']

    print("Successful login.")
    print("Requesting upload job...")
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Authorization': 'Bearer {0}'.format(session_token)
    }

    response = requests.post('http://localhost:8080/api/v2/file-upload/start', headers=headers)


    response_content = response.content.decode('utf-8')

    json_obj = json.loads(response_content)
    uploadID = json_obj['data']['id']
    print("Created login job: {0}".format(uploadID))

    print("Parsing file {0}".format(args.file))

    headers = {
        'accept': '*/*',
        'Authorization': 'Bearer {0}'.format(session_token),
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    with open(args.file, mode='rb') as f:
        data = f.read()
    print("Finished loading file.")
    print("Uploading file...")
    response = requests.post('http://localhost:8080/api/v2/file-upload/{0}'.format(uploadID), headers=headers, data=data)
    print("Upload complete.")
    print("Allowing 10 seconds to assert file upload complete...")
    time.sleep(10)
    print("Ending job...")
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9,es;q=0.8,fr;q=0.7',
        'Authorization': 'Bearer {0}'.format(session_token)
    }

    response = requests.post('http://localhost:8080/api/v2/file-upload/{0}/end'.format(uploadID), headers=headers)

    print("Completed uploading file. Check BloodHound UI for processing information (it may take a while before showing up).")

if __name__ == "__main__":
    main()