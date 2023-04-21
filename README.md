# Intrustion-Detection-System

This script analyzes a given pcap file to detect malicious traffic, such as phishing attempts, malware delivery, brute force attacks, DDoS attacks, and C&C traffic.

Overview
The script fetches updated malicious IP, domain, and signature definitions from specified sources and uses them to analyze the provided pcap file. It logs any detected malicious packets and the type of attack they are associated with.

Dependencies
To run this script, you will need the following Python packages:

pyshark
requests

You can install them using pip:

pip install pyshark requests

How to Use
The script can be run from the command line, with the following arguments:

-f or --file: Path to the pcap file to be analyzed (required)
-t or --threshold: Threshold for brute force attack detection (default: 5)
-w or --time-window: Time window for brute force attack detection in seconds (default: 60)
-d or --ddos-threshold: Threshold for DDoS attack detection (default: 100)
-p or --ddos-time-window: Time window for DDoS attack detection in seconds (default: 10)
-o or --output: Path to the output file (optional)
-v or --verbose: Increase output verbosity (optional)
For example, to analyze a pcap file named example.pcap and log the results in output.log:

python malicious_traffic_detector.py -f example.pcap -o output.log -v

Configuration
To configure the sources for malicious definitions, edit the malicious_definitions.json file. You can add or remove sources for URLS to updating Intelligence Threat Feeds for IPs, domains, and signatures as needed. The script will fetch and cache data from these sources before analyzing the pcap file.
