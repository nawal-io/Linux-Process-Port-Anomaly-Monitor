# Linux CLI Process & Port Anomaly Monitor

A lightweight, zero-dependency Python Command Line Interface (CLI) utility built to audit active Linux processes and flag potential security anomalies, such as reverse shell spawns, rogue mining scripts, or unauthorized network utility bindings.

## Features
- **Zero Third-Party Dependencies:** Built entirely with standard Python 3 libraries (`subprocess`, `re`, `json`, `datetime`).
- **Native OS Integration:** Leverages system calls (`ps`) to query runtime process lists and command-line execution arguments.
- **Threat Indicator Detection:** Automatically scans for suspicious binary executions (`nc`, `ncat`, interactive shell payloads) and unauthorized high-risk port flags (`4444`, `1337`, `31337`).

## Getting Started

### Prerequisites
- Python 3.x
- Linux / Unix-based Environment (Kali Linux, Ubuntu, WSL, etc.)

### Usage

1. Clone this repository:
```bash
git clone https://github.com/nawal-io/Linux-Process-Port-Anomaly-Monitor.git
cd Linux-Process-Port-Anomaly-Monitor
```

2. Run the monitor script:
```bash
python3 process_monitor.py
```

## Author
- **Nawal Aulia Hasan Hunaifa** - [nawal-io](https://github.com/nawal-io)
