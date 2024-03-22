import requests
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import hashes

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

TEAMSERVER = "127.0.0.1"
INT = 50050


KEY = get_random_bytes(32)
nonce = get_random_bytes(12)
SESSION_KEY = nonce + b"\x00" * 4 + KEY
aesgcm = AESGCM(KEY)

data = {"port": "80"}

req_1 = {"UID": "asdiu1o2nj", "IP": "1.1.1.1", "State": 0x45}

if __name__ == "__main__":
    r = requests.post(f"http://{TEAMSERVER}:{INT}/start", json=data)
    r = requests.post(f"http://{TEAMSERVER}:80/register", json=req_1)
    pk = r.json()["public_key"]
    pk_b64 = base64.b64decode(pk)

    public_key_json = json.loads(pk_b64)
    public_key_components = RSAPublicNumbers(public_key_json["E"],
                                             public_key_json["N"]).public_key(
                                                 default_backend())

    rsa_pk = public_key_components.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    public_key = serialization.load_pem_public_key(rsa_pk, default_backend())
    """
    iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
    """

    encrypted = public_key.encrypt(
        SESSION_KEY,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))

    b64_encrypted = base64.b64encode(encrypted).decode()
    print(b64_encrypted)

    req2 = {
        "UID": "asdiu1o2nj",
        "IP": "1.1.1.1",
        "State": 0x60,
        "Optional": b64_encrypted
    }
    r = requests.post(f"http://{TEAMSERVER}:80/register", json=req2)
    print(r.text)
    print(SESSION_KEY.hex())
    agent_data = {
        "IP": "1.1.1.1",
        "ExtIP": "1.1.1.1",
        "Hostname": "test",
        "Sleep": "60",
        "Jitter": "10",
        "OS": "Windows",
        "UID": "asdiu1o2nj",
        "PID": "1234",
    }

    string_agent_data = json.dumps(agent_data)
    encrypted_data = aesgcm.encrypt(nonce, string_agent_data.encode(), None)
    b64_cipher = base64.b64encode(encrypted_data).decode()

    req3 = {
        "UID": "asdiu1o2nj",
        "IP": "1.1.1.1",
        "State": 0x90,
        "Optional": b64_cipher
    }
    r = requests.post(f"http://{TEAMSERVER}:80/register", json=req3)
    print(r.text)
