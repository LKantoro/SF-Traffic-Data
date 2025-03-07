import pandas as pd
import requests
from requests.adapters import HTTPAdapter, Retry

class HTTPClient:
    def __init__(
        self,
        retry_attempts=3,
        backoff_factor=0.3,
        timeout=5,
        session=None,
    ):
        self.retry_attempts = retry_attempts
        self.backoff_factor = backoff_factor
        self.session = session or requests.Session()
        self.timeout = timeout
        self._configure_retry_policy()

    def _configure_retry_policy(self):
        retry_strategy = Retry(
            total=self.retry_attempts,
            backoff_factor=self.backoff_factor,
            allowed_methods=set(Retry.DEFAULT_ALLOWED_METHODS) | set(["POST"]),
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url, **kwargs):
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url, **kwargs):
        return self.session.post(url, timeout=self.timeout, **kwargs)



import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import json


http_client = HTTPClient(timeout=4, retry_attempts=4)


def get_data(url: str = "https://web.pulsepoint.org/DB/giba.php?agency_id=EMS1384") -> dict:
    data = http_client.get(url).json()

    ct = base64.b64decode(data.get("ct"))
    iv = bytes.fromhex(data.get("iv"))
    salt = bytes.fromhex(data.get("s"))

    # Build the password
    t = ""
    # e = 'IncidentsCommon'
    e = "CommonIncidents"
    t += e[13] + e[1] + e[2] + "brady" + "5" + "r" + e.lower()[6] + e[5] + "gs"

    # Calculate a key from the password
    hasher = hashlib.md5()
    key = b""
    block = None

    while len(key) < 32:
        if block:
            hasher.update(block)
        hasher.update(t.encode())
        hasher.update(salt)
        block = hasher.digest()
        hasher = hashlib.md5()
        key += block

    # Create a cipher and decrypt the data
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ct) + decryptor.finalize()

    # Clean up output data
    decrypted_data = decrypted_data[1: decrypted_data.rindex(b'"')].decode()  # Strip off extra bytes and wrapper quotes
    decrypted_data = decrypted_data.replace(r"\"", r'"')  # Un-escape quotes

    data = json.loads(decrypted_data)
    # print(data)
    # active = data.get("incidents", {}).get("active", {})
    # [print("%s @ %s" % (c.get("PulsePointIncidentCallType"), c.get("FullDisplayAddress"))) for c in active]

    return data

apple = get_data()
#print(apple)

df = pd.json_normalize(apple)

#print(df)

print(type(df))

print(df.iloc[0,1])

print(type(df.iloc[0,2]))

print(pd.DataFrame(df.iloc[0,1])) #active
active = pd.DataFrame(df.iloc[0,1])


print(pd.DataFrame(df.iloc[0,2])) #recent
recent = pd.DataFrame(df.iloc[0,2])

#active.to_csv('active.csv', index=True)

recent.to_csv('recentSunday.csv', index=True)

#utc is 8 hours ahead of PST

#format the time differently - filter by Traffic Collisions TC

#Latitude and Longtidue coordinates

#


#look at more regions
#wite down process for reproduciblity

#crash data collected

#open data sf is citywide data

#opendatasf and pulse point trying to compar
