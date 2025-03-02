# Network Sniffer

## **Objective**
The **Network Sniffer** is a tool designed to **capture, analyze, and log network traffic**. It helps network administrators and security professionals **monitor network activity, detect suspicious traffic, and troubleshoot connectivity issues**.

## **How It Works**
1. **Sniffs live packets from a network interface (Wi-Fi/Ethernet).**
2. **Analyzes packet headers and payloads.**
3. **Filters packets based on protocol (TCP, UDP, ICMP, HTTP, DNS).**
4. **Logs captured data in JSON format.**
5. **Provides a GUI for real-time monitoring.**
6. **Stores logs for forensic analysis.**

## **Use Cases**
- **Detecting suspicious network activity (MITM attacks, DNS hijacking).**
- **Monitoring network traffic for debugging and performance analysis.**
- **Logging and analyzing packets for forensic investigations.**
- **Capturing HTTP/DNS requests for security auditing.**

## **Installation**
```bash
pip install -r requirements.txt
