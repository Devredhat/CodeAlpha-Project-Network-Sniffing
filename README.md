# CodeAlpha Project: Network Sniffing

![GitHub repo size](https://img.shields.io/github/repo-size/Devredhat/CodeAlpha_Project_Network_Sniffing?style=flat-square)
![GitHub stars](https://img.shields.io/github/stars/Devredhat/CodeAlpha_Project_Network_Sniffing?style=social)
![GitHub forks](https://img.shields.io/github/forks/Devredhat/CodeAlpha_Project_Network_Sniffing?style=social)

This Python script is designed to monitor HTTP traffic on a network interface using Scapy. It captures details such as protocol (TCP/UDP), IP addresses, ports, HTTP methods, paths, form data, and user-agent information. The captured requests are displayed in a structured table format, highlighting critical details for each request, including browser information and submitted form data.

## 🚀 Key Features

- **Real-time Monitoring:** Captures and displays HTTP requests and responses in real-time.
- **Detailed Analysis:** Provides comprehensive details like protocol types, IP addresses, ports, and HTTP header contents.
- **User-Agent Parsing:** Extracts and interprets browser and operating system information from user-agent strings.
- **Form Data Extraction:** Decodes and presents form submissions sent via HTTP POST requests.
- **Customizable Filtering:** Allows filtering of specific network traffic patterns for focused monitoring.

## 🔧 Requirements

- Python 3.x
- Scapy
- PrettyTable
- user_agents

## 📖 Usage

1. Ensure Python and required dependencies are installed (`pip install -r requirements.txt`).
2. Run the script (`python networksniff.py`).
3. Observe HTTP traffic on the specified network interface.
4. Terminate monitoring by pressing Ctrl+C.

## 🌐 Explore More

Check out the [project on GitHub](https://github.com/Devredhat/CodeAlpha_Project_Network_Sniffing) for detailed documentation, issues, and contributions.

---

Enhance your network monitoring capabilities with CodeAlpha Project's Network Sniffing tool! Feel free to customize and expand this README.md further to showcase more details, screenshots, or additional features of your project.
