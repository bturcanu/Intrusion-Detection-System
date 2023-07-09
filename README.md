# Intrusion-Detection-System

**This script is designed to analyze network traffic captured in pcap files and identify malicious activities, such as phishing attempts, malware delivery, brute force attacks, distributed denial of service (DDoS) attacks, and command and control (C&C) traffic.**

## Overview

The Intrusion Detecton System script is a comprehensive network traffic analysis tool that helps network administrators and security professionals identify and mitigate potential security threats. By utilizing updated malicious IP, domain, and signature definitions, it inspects network traffic to detect patterns indicative of malicious behavior.

The script performs the following tasks:

1. **Fetch and cache malicious definitions:** The script downloads the latest definitions of malicious IPs, domains, and signatures from specified sources in the malicious_definitions.json configuration file. These definitions are cached to improve performance during analysis.

2. **Read pcap file:** The script reads the provided pcap file, which contains captured network traffic, using the pyshark library.

3. **Analyze traffic:** Each packet in the pcap file is analyzed for signs of malicious activity. The script checks for known malicious IPs and domains, as well as traffic patterns indicative of attacks (e.g., brute force, DDoS).

4. **Log detected threats:** If a packet is found to be malicious, the script logs information about the packet, the type of threat it represents, and any additional details that may aid in understanding the threat (e.g., source and destination IPs, domain, attack signature).

5. **Output results:** The script provides a summary of detected threats, including the total number of threats and a breakdown of threats by category. This information can be printed to the console or saved to a specified output file.

## Dependencies
To run this script, you will need the following Python packages:

- **pyshark**
- **requests**

You can install them using pip:

```console
pip install pyshark requests
```

## How to Use

The script can be run from the command line, with the following arguments:

- `-f` or `--file`: *Path to the pcap file to be analyzed (required)*
- `-t` or `--threshold`: *Threshold for brute force attack detection (default: 5)*
- `-w` or `--time-window`: *Time window for brute force attack detection in seconds (default: 60)*
- `-d` or `--ddos-threshold`: *Threshold for DDoS attack detection (default: 100)*
- `-p` or `--ddos-time-window`: *Time window for DDoS attack detection in seconds (default: 10)*
- `-o` or `--output`: *Path to the output file (optional)*
- `-v` or `--verbose`: *Increase output verbosity (optional)*

For example, to analyze a pcap file named `example.pcap` and log the results in `output.log`:

```console
python IntrustionDetector.py -f example.pcap -o output.log -v
```


## Configuration

Configuration is designed for ease of use and can be customized to suit the specific needs of your network environment. To configure the sources for malicious definitions, edit the `malicious_definitions.json` file. You can add or remove URLS to updating Intelligence Threat Feeds that contain malicious IPs, domains, and signatures as needed. The script will fetch and cache data from these sources before analyzing the pcap file.
