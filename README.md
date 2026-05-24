# MQTT-iot-security-analysis
MSc Cyber Security dissertation — Packet-level analysis of normal vs malicious MQTT traffic in a GNS3 virtualised IoT environment. Includes brute-force, flooding DoS, replay, and topic hijacking attack scripts plus K-Means unsupervised clustering analysis.


This repository contains all source code, configuration files, and 
analysis scripts produced for the MSc Cyber Security dissertation:

"Security Challenges in IoT Devices: Analysis of Firmware and 
Protocol Vulnerabilities"

Muhammad Hassan Farooq | Student ID: 100766896
University of Derby | Supervisor: Dr. Haider Ali | May 2026

---

RESEARCH QUESTION
How does malicious MQTT traffic differ from normal MQTT traffic at 
the packet level in a virtualised IoT environment, and how is it 
identifiable via packet-level analysis?

---

WHAT THIS PROJECT DOES
A three-node GNS3 laboratory was built comprising a Mosquitto MQTT 
broker, a Python paho-mqtt IoT publisher, and a Kali Linux attacker 
node. Four attack scenarios were executed in isolation and captured 
in Wireshark:

  - Brute-force credential attack (406 packets, 34x CONNACK rc=5)
  - Flooding denial-of-service (215,728 packets, 1,438 pkt/sec)
  - Payload replay attack (88 packets, dual-source PUBLISH)
  - Topic hijacking (74 packets, wildcard SUBSCRIBE + SYSTEM OVERRIDE)

K-Means unsupervised clustering (k=3) was applied to 7 packet-level 
features extracted from 5 Wireshark .pcap files, confirming three 
statistically distinct traffic clusters without any labelled training 
data. Silhouette score: 0.4829.

---

KEY FINDING
Replay and topic hijacking attacks are volumetrically 
indistinguishable from normal traffic — both operate at near-baseline 
packet rates (1.34-1.35 pkt/sec vs 0.66 baseline). Volume-based 
detection alone is insufficient. Deeper inspection of SUBSCRIBE 
patterns and dual-source PUBLISH behaviour is required.

---

ENVIRONMENT
  - GNS3 2.2.x with QEMU virtual machines
  - Mosquitto 2.0 on Ubuntu 22.04 (port 1883, auth enabled)
  - Python 3 + paho-mqtt on Ubuntu 22.04
  - Kali Linux 2025.4
  - Subnet: 192.168.35.0/24
  - Wireshark 4.x
  - scikit-learn in Google Colab

---

NOTE ON PCAP FILES
Wireshark capture files are not included in this repository due to 
file size constraints (flooding DoS capture is 229MB). 
