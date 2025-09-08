## Python Firewall with GUI

A simple, proof-of-concept application-layer firewall built with Python and Scapy. This project features a graphical user interface (GUI) made with Tkinter for educational demonstration, allowing users to dynamically filter network traffic based on custom rules.

## Features

- **IP Filtering**: Dynamically add or remove IP addresses to block.
- **Protocol Blocking:** Toggle to block specific protocols (TCP, UDP, ICMP).
- **Real-time Logging:** Live log display of all blocked packets with details.
- **User-Friendly GUI:** Intuitive interface for easy interaction.
- **Educational Tool:** Demonstrates core networking and cybersecurity concepts.

## Built With

- **Python** - The programming language used.
- **Scapy** - Packet manipulation library.
- **Tkinter** - Standard GUI library for Python (included in standard library).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MrThamz04/Python-Firewall-GUI.git
    cd python firewall_gui
    ```

2.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: The only dependency is `scapy`)*

##  Usage

1.  **Run the application with administrator/root privileges** (essential for accessing network interfaces):
    ```bash
    # On Windows: Open Command Prompt as Administrator, then run:
    python firewall_gui.py

    # On Linux/macOS:
    sudo python3 firewall_gui.py
    ```

2.  **Using the GUI:**
    - **IP Management:** Enter an IP address in the text field and click "Add" to block it. Select an IP from the list and click "Remove Selected" to unblock it.
    - **Protocol Management:** Check the boxes for the protocols (TCP, UDP, ICMP) you wish to block.
    - **Start/Stop:** Click "Start Firewall" to begin filtering traffic. Click "Stop Firewall" to halt.
    - **Logs:** View all blocked packet information in the real-time log area.


##  How It Works

- The script uses the **Scapy** library to capture and inspect network packets in real time.
- A custom filter function checks each packet against the user-defined rules (IPs and protocols).
- Packets that match the block rules are dropped and logged to the GUI.
- The **Tkinter** GUI runs in the main thread, while **Scapy's packet sniffing** runs in a separate daemon thread to keep the interface responsive.


##  Disclaimer

**This project is for educational and demonstration purposes only.** It is a simplified version of a firewall and should not be used as a primary security measure in a production environment. The author is not responsible for any misuse of this tool.

##  Developer

- **Tinaye Nickson Hamandishe** - https://github.com/MrThamz04
- Computer Science Student | Aspiring Penetration Tester | Cybersecurity Enthusiast | Data Enthusiast


