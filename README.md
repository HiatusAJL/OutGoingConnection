# Outgoing Connections Viewer

## Description
This Python script provides a graphical user interface to monitor and manage outgoing TCP connections on a Windows system. It utilizes netstat to fetch current connections, displays them in a sortable table, and offers options to terminate processes or explore them further in the Task Manager.

## Features
- Real-time monitoring of outgoing TCP connections.
- Options to terminate processes or inspect them in Task Manager.
- Uses IPinfo and AbuseIPDB to fetch IP details and reputation scores.

## Requirements
- Python 3
- Libraries: tkinter, psutil, requests, ipinfo
- Windows OS

## Setup
1. Install Python and pip.
2. Install required Python libraries:
   ```bash
   pip install requests psutil ipinfo
