import paho.mqtt.client as mqtt
import time
import json
import random

BROKER = "192.168.35.143"
PORT = 1883
TOPIC = "sensors/telemetry"

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

print("Publishing normal MQTT traffic... Press Ctrl+C to stop")
while True:
    payload = json.dumps({
        "temperature": round(random.uniform(20.0, 30.0), 2),
        "humidity": round(random.uniform(40.0, 70.0), 2)
    })
    client.publish(TOPIC, payload)
    print(f"Published: {payload}")
    time.sleep(5)