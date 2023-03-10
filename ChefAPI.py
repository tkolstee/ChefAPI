"""
See Also:
https://github.com/chef-boneyard/chef-rfc/blob/master/rfc065-sign-v1.3.md
https://docs.chef.io/server/api_chef_server/
"""

import os
import base64
import re
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
from datetime import datetime, timezone
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256


class ChefAPI:
    def __init__(self, url, keyfile, userid, verify=True):
        if not os.path.exists(keyfile):
            raise FileNotFoundError("Key file not found")
        with open(keyfile, 'r') as f:
            keydata = f.read()
        self.key = RSA.import_key(keydata)
        self.userid = userid
        self.url = url
        self.host = urlparse(url).netloc
        self.verify = verify
    
    def content_hash(self, body):
        if type(body) == bytes:
            hash = body
        else:
            hash = body.encode()
        hash = SHA256.new(hash).digest()
        hash = base64.b64encode(hash).decode()
        return hash

    def timestamp(self):
        now = datetime.utcnow()
        now = now.replace(microsecond=0).replace(tzinfo=timezone.utc)
        now = now.isoformat()
        now = re.sub(r'\+00:00', 'Z', now)
        return now

    def headers(self, path, method, body=None):
        headers = {
            'Accept': 'application/json',
            'Host': self.host,
            'Method': method,
            'Path': path,
            'X-Chef-Version': '16.0.0',
            'X-Ops-Content-Hash': self.content_hash(body or ''),
            'X-Ops-Server-API-Version': '1',
            'X-Ops-Sign': 'version=1.3',
            'X-Ops-Timestamp': self.timestamp(),
            'X-Ops-UserId': self.userid
        }
        if (body):
            headers['Content-Type'] = 'application/json'
        
        headers.update(self.signing_headers(headers))
        return headers

    def canonical_headers(self, headers):
        return "\n".join(
            f"{x}:{headers[x]}"
            for x in [
                'Method', 
                'Path',
                'X-Ops-Content-Hash', 'X-Ops-Sign', 
                'X-Ops-Timestamp', 'X-Ops-UserId', 'X-Ops-Server-API-Version'
            ]
        )

    def gen_signature(self, message):
        plaintext = message
        if type(message) == str:
            plaintext = plaintext.encode()
        hash = SHA256.new(plaintext)
        key = self.key
        pkcs = pkcs1_15.new(key)
        sig = pkcs.sign(hash)
        b64 = base64.b64encode(sig)
        return b64.decode()

    def signing_headers(self, headers):
        content = self.canonical_headers(headers)
        sig = self.gen_signature(content)
        newheaders = {}
        for i, idx in enumerate(range(0, len(sig), 60)):
            fragment = sig[0+idx:60+idx]
            newheaders[f"X-Ops-Authorization-{i+1}"] = fragment
        return newheaders

    def get(self, request):
        url = f"{self.url}{request}"
        parsed_url = urlparse(url)
        headers = self.headers(parsed_url.path, 'GET')
        r = requests.get(url, headers=headers, verify=self.verify)
        return r
        
