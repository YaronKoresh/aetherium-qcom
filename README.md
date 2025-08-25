# Aetherium Q-Com

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

Aetherium Q-Com is a secure communication platform featuring a novel, quantum-inspired key exchange protocol with AI-driven security and a full suite of chaos-based cryptographic tools for end-to-end encrypted P2P and group messaging.

**Author:** [Yaron Koresh](mailto:aharonkoresh1@gmail.com)

---

## Table of Contents
- [Quick Install & Run](#quick-install--run)
- [Project Overview](#project-overview)
- [Key Features](#key-features)
- [How It Works: The Protocol](#how-it-works-the-protocol)
- [Usage Guide](#usage-guide)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Quick Install & Run

This is the easiest way to get started. These scripts will automatically install Python dependencies and the application itself.

### Windows
1.  Download the `run_aeterium.bat` file.
2.  Double-click the file to run it. A command prompt will open and install the necessary components from GitHub.
3.  Once complete, the application will launch automatically.

### macOS & Linux
1.  Download the `run_aeterium.sh` file.
2.  Open your terminal and navigate to the directory where you saved the file.
3.  Make the script executable by running: `chmod +x run_aeterium.sh`
4.  Execute the script: `./run_aeterium.sh`
5.  The script will install the dependencies and launch the application.

After the first installation, you can run the application anytime by simply typing `aetherium-qcom` in your terminal.

---

## Project Overview

Aetherium Q-Com simulates a quantum key distribution (QKD) protocol without requiring specialized quantum hardware. It establishes a provably secure communication channel between users by combining several principles:

1.  **Classical Key Agreement:** A Diffie-Hellman exchange securely establishes an initial shared secret.
2.  **Chaotic Synchronization:** This secret seeds a pair of coupled chaotic oscillators which are used to generate quantum-style measurement bases.
3.  **Simulated Quantum Channel:** A central, untrusted "Host" node simulates Bell State Measurements, mimicking how real QKD systems interact with photons.
4.  **AI-Powered Security:** A Bayesian AI agent actively monitors the channel for statistical anomalies (QBER, SNR, etc.) that would indicate an eavesdropping attempt, aborting the connection if necessary.

The result is a highly secure key, which is then used to power an end-to-end encrypted, chaos-based stream cipher for live communication.

---

## Key Features

- **Quantum-Inspired Key Exchange:** Utilizes a protocol simulating Bell State Measurements and synchronized chaotic systems to securely generate a shared cryptographic key.
- **AI-Powered Anomaly Detection:** An intelligent Bayesian defense system monitors channel statistics in real-time to detect and thwart man-in-the-middle attacks.
- **Chaos-Based Cryptography:** Employs a fast and secure stream cipher derived from the synchronized state of a logistic map, ensuring all communications are end-to-end encrypted.
- **Secure P2P & Group Chat:** Provides a user-friendly interface for both direct P2P messaging and multi-user group chats.
- **Secure Group Key Distribution:** The owner of a group chat automatically wraps and securely distributes the group encryption key to each member using their pre-established P2P keys.
- **Decentralized-Friendly Architecture:** The system relies on user-hosted relay nodes ("Hosts") which do not need to be trusted, as the security of the protocol is guaranteed mathematically.

---

## How It Works: The Protocol

The key exchange process is divided into distinct phases:

1.  **Phase 1: Seeding:** Two users connect to a Session Host and perform a Diffie-Hellman key exchange.
2.  **Phase 2: Synchronization:** Each user initializes a `CoupledChaoticSystem` with the shared secret. Over thousands of "pulses," they send simulated quantum states to the Host which returns the outcome of a simulated Bell State Measurement.
3.  **Phase 3: Sifting & Analysis:** Periodically, the users communicate directly (P2P) to compare the bases they used. This "sifting" process reveals the Quantum Bit Error Rate (QBER), which is fed to the `IntelligentDefense` AI.
4.  **Phase 4: Final Key Generation:** Once all pulses are sent and the AI deems the channel secure, the final synchronized state of the users' chaotic oscillators is used as the seed for the `QuantumSentryCryptography` suite.

---

## Usage Guide

Aetherium is a live platform requiring at least two users. The system consists of **Hosts** (relays) and **Clients** (users). Any user can run a Host.

**1. Launch the Application**
- After following the **Quick Install** guide, open a new terminal (or Command Prompt on Windows) and run the command: `aetherium-qcom`
- The application window will open.

The rest of the usage for P2P and Group chats remains the same. One user must launch a **P2P Host** or **Group Host**, and other users can then connect to create or join sessions.

---

## Troubleshooting

- **Command not found**: If the aetherium-qcom command is not found after running the installation script, try closing and reopening your terminal. Your system's PATH may need to be refreshed. On Windows, you may need to restart your computer.
- **Firewall Issues**: For connections over the internet, the user hosting a relay will need to configure port forwarding on their router for the relevant ports (e.g., P2P Host uses port 65000).

---

## Contributing

- Before asking for support, please make sure you are using the [latest version](https://github.com/YaronKoresh/aetherium-qcom).
- To report bugs or suggest enhancements, please search the [open or closed issues](https://github.com/YaronKoresh/aetherium-qcom/issues?q=is%3Aissue) before opening a new one.
 
