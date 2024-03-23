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


def start_listener():
    """
    50050
    """

    data = {"type": "http"}
    r = requests.post(f"http://{TEAMSERVER}:{INT}/start_listener", json=data)
    print(r.text)


def register():
    """
    80
    """
    req_1 = {"UID": "agent123", "IP": "1.1.1.1", "State": 0x45}
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

    encrypted = public_key.encrypt(
        SESSION_KEY,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))

    b64_encrypted = base64.b64encode(encrypted).decode()

    req2 = {
        "UID": "agent123",
        "IP": "1.1.1.1",
        "State": 0x60,
        "Optional": b64_encrypted
    }

    r = requests.post(f"http://{TEAMSERVER}:80/register", json=req2)

    agent_data = {
        "IP": "8.1.1.1",
        "ExtIP": "1.1.1.1",
        "Hostname": "test",
        "Sleep": "60",
        "Jitter": "10",
        "OS": "Windows",
        "UID": "agent123",
        "PID": "1234",
    }

    string_agent_data = json.dumps(agent_data)
    encrypted_data = aesgcm.encrypt(nonce, string_agent_data.encode(), None)
    b64_cipher = base64.b64encode(encrypted_data).decode()

    req3 = {
        "UID": "agent123",
        "IP": "1.1.1.1",
        "State": 0x90,
        "Optional": b64_cipher
    }

    r = requests.post(f"http://{TEAMSERVER}:80/register", json=req3)
    print(r.text)

def checkin():
    data = "agent123"
    r = requests.post(f"http://{TEAMSERVER}:80/changethis", data=data)
    task = r.json()["task"]
    b64_decoded = base64.b64decode(task)
    decrypted = aesgcm.decrypt(nonce, b64_decoded, None)
    print(decrypted)

def send_a_task():
    task = {
        "Agent": {
            "IP": "192.168.1.1",
            "ExtIP": "203.0.113.1",
            "Hostname": "agent-host",
            "Sleep": "60",
            "Jitter": "10",
            "OS": "Windows",
            "UID": "agent123",
            "PID": "4567"
        },
        "Task": {
            "UID": "agent123",
            "CommandID": "cmd001",
            "Command": "ls -la"
        }
    }

    r = requests.post(f"http://{TEAMSERVER}:50050/task", json=task)
    print(r.text)




if __name__ == "__main__":
    start_listener()
    register()
    send_a_task()
    checkin()
