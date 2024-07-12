# HTTP Traffic Monitor

![GitHub repo size](https://img.shields.io/github/repo-size/your_username/your_repo_name)
![GitHub stars](https://img.shields.io/github/stars/Devredhat/CodeAlpha_Project_Network_Sniffing)
![GitHub forks](https://img.shields.io/github/forks/your_username/your_repo_name?style=social)

This Python script monitors HTTP traffic on a network interface using Scapy, capturing details such as protocol (TCP/UDP), IP addresses, ports, HTTP methods, paths, form data, and user-agent information. It displays captured requests in a structured table format, highlighting critical details for each request, including browser information and submitted form data.

## Key Features

- **Real-time Monitoring:** Captures and displays HTTP requests and responses as they occur.
- **Detailed Analysis:** Provides comprehensive details like protocol types, IP addresses, ports, and HTTP header contents.
- **User-Agent Parsing:** Extracts and interprets browser and operating system information from user-agent strings.
- **Form Data Extraction:** Decodes and presents form submissions sent via HTTP POST requests.
- **Customizable Filtering:** Allows filtering of specific network traffic patterns for focused monitoring.

## Requirements

- Python 3.x
- Scapy
- PrettyTable
- user_agents

## Usage

1. Ensure Python and required dependencies are installed (`pip install -r requirements.txt`).
2. Run the script (`python http_traffic_monitor.py`).
3. Observe HTTP traffic on the specified network interface.
4. Terminate monitoring by pressing Ctrl+C.

Feel free to customize the badges and add more sections as needed to enhance your repository's README.md file.
