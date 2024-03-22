import requests

TEAMSERVER = "127.0.0.1"
INT = 50050

data = {
    "port": "80"
}

agent_data = {
    "IP": "192.168.1.1",
    "ExtIP": "93.184.216.34",
    "Hostname": "example-agent",
    "Sleep": "5s",
    "Jitter": "2s",
    "OS": "Linux",
    "UID": "agent123",
    "PID": "456"
}

if __name__ == "__main__":
    r = requests.post(f"http://{TEAMSERVER}:{INT}/start", json=data)
    print(r.text)

    # r = requests.post(f"http://{TEAMSERVER}:{INT}/stop", json=data)
    # print(r.text)

    r = requests.post(f"http://{TEAMSERVER}:80/register", json=agent_data)
    print(r.text)
    