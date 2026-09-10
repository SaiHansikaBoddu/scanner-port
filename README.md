# NetScan // Web-Based Network Security Port Scanner

A clean, beginner-friendly Web-Based TCP Port Scanner designed for academic cybersecurity demonstrations. Built using **pure Vanilla HTML/CSS/JavaScript** for the frontend and **Python standard libraries** (`http.server`, `socket`, `json`) for the backend.

No third-party frameworks (no Flask, Django, React, Docker, or external databases) are required.

---

## 📁 Project Structure

```text
Port Scanner/
├── backend/
│   └── scanner.py          # Python standard library HTTP server + TCP socket scanner
├── frontend/
│   ├── index.html          # Cyber-themed modern user interface
│   ├── style.css           # Vanilla CSS (dark theme, glassmorphic cards, neon accents)
│   └── script.js           # Vanilla JS for API communication, validation & table filtering
├── README.md               # Project documentation and theoretical guide
└── requirements.txt        # Documentation of zero-dependency standard library usage
```

---

## 🎯 Project Objective

The objective of this project is to demonstrate core transport-layer reconnaissance and client-server socket programming concepts within a web-based dashboard:
- How web clients communicate with a local Python backend via HTTP/JSON.
- How Python's `socket` library establishes low-level TCP connections to inspect remote or local ports.
- How to interpret TCP port states (`OPEN` vs. `CLOSED`) based on connection responses.
- How to identify standard network services (HTTP, HTTPS, SSH, DNS, SMB, MySQL, RDP) mapped to port numbers.

---

## ✨ Features

- **Cybersecurity Dark UI:** Sleek, responsive interface featuring deep slate backgrounds, glassmorphism, and neon green/cyan indicators suitable for college project presentations.
- **Dynamic Port Scanning:** Scans user-specified port ranges (from port `1` to `65535`) on any IP address or hostname.
- **Service Name Resolution:** Maps scanned ports to standard protocols (e.g. Port `80` $\rightarrow$ `HTTP`, Port `443` $\rightarrow$ `HTTPS`, Port `135` $\rightarrow$ `MS-RPC`, Port `3306` $\rightarrow$ `MySQL`).
- **Real-Time Results Table:** Clearly distinguishes `● OPEN` (green glow) and `○ CLOSED` ports.
- **Interactive Controls:**
  - Quick target selection chips (`127.0.0.1`, `localhost`, `scanme.nmap.org`).
  - Pre-configured port range presets (Common Low, Web HTTP, RPC/SMB, SSL/HTTPS, MySQL).
  - Search filter (filter results live by port number or service name).
  - Filter tabs (`All`, `Open Only`, `Closed Only`).
- **Summary Metrics:** Shows Target, Resolved IP, Ports Scanned, Total Open Count, and Scan Duration in seconds.
- **Robust Error Handling:**
  - Validates missing or invalid hostnames / IPs (`socket.gaierror`).
  - Validates non-integer or out-of-range port numbers.
  - Rejects cases where starting port is greater than ending port.
  - Displays user-friendly error banners on the UI.
- **Zero Third-Party Dependencies:** Uses only Python's built-in standard library (`http.server`, `socket`, `json`, `time`, `datetime`).

---

## 🛠 Technologies Used

- **Frontend:**
  - **HTML5:** Semantic layout and structured components.
  - **CSS3 (Vanilla):** Custom cybersecurity dark styling, CSS Grid, Flexbox, glassmorphism, animations, and Google Fonts (`Inter` & `JetBrains Mono`).
  - **JavaScript (ES6+ Vanilla):** Form validation, `fetch()` API calls, and DOM rendering.
- **Backend:**
  - **Python 3:** Core programming language.
  - **Standard Libraries:**
    - `http.server` & `BaseHTTPRequestHandler` — Built-in HTTP web server and JSON API endpoint.
    - `socket` — Network socket stream management and DNS resolution.
    - `json` — Serialization and parsing of request/response payloads.
    - `time` & `datetime` — Scan performance benchmarking and timestamps.

---

## 🚀 How to Run the Project

### Step 1: Start the Python Backend Server
1. Open a terminal or command prompt.
2. Navigate to the project directory:
   ```bash
   cd "c:\Users\hansi\OneDrive\Desktop\cyber security tasks\Port Scanner"
   ```
3. Start the backend scanner server:
   ```bash
   python backend/scanner.py
   ```
4. You will see output confirming the server is active:
   ```text
   =================================================================
         NETWORK SECURITY PORT SCANNER - WEB BACKEND SERVER
   =================================================================
    [+] Python Backend running at : http://127.0.0.1:8000
    [+] Web Interface URL        : http://localhost:8000
    [+] API Endpoint             : http://127.0.0.1:8000/api/scan
    [+] Press Ctrl+C in this terminal to stop the server.
   =================================================================
   ```

### Step 2: Open the Web Frontend
Open your favorite web browser (Chrome, Edge, Firefox, Brave) and navigate to:
```text
http://localhost:8000
```
*(Alternatively, you can double-click `frontend/index.html` directly in your file explorer; the application supports cross-origin requests out of the box).*

---

## 💻 Example Usage

1. **Enter Target:** Type `127.0.0.1` (or click the `127.0.0.1` quick button).
2. **Enter Port Range:** Enter Starting Port `130` and Ending Port `145` (or select the `130 – 145 (RPC/SMB)` preset).
3. **Click "Scan Ports":**
   - The button shows a loading spinner while the backend inspects the ports.
   - The metrics update to display:
     - **Target Host:** `127.0.0.1`
     - **Resolved IP:** `127.0.0.1`
     - **Scanned Range:** `130 – 145 (Total: 16 ports)`
     - **Open Ports:** `1 OPEN` (e.g., `Ports: 135`)
     - **Duration:** `~1.2s`
   - The table renders rows with port numbers, protocol (`TCP`), service names (e.g. `MS-RPC (Microsoft RPC)`), and colored status badges (`OPEN` / `CLOSED`).

---

## 🔍 How Port Scanning Works

### The TCP Three-Way Handshake
Under standard Transmission Control Protocol (TCP) operations:
1. **SYN (Synchronize):** The scanner sends a SYN packet to the target port.
2. **SYN-ACK or RST:**
   - **Open Port:** If a service is listening, the target host replies with **SYN-ACK**.
   - **Closed Port:** If no service is listening, the operating system replies with **RST** (Reset) to refuse connection.
3. **ACK:** The client completes the handshake if needed or immediately terminates with **RST/FIN**.

### How `socket.connect_ex()` Works in Python
In `backend/scanner.py`, each port is tested using:
```python
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.35)
result_code = s.connect_ex((target_ip, port))
```
- Return code `0`: Socket successfully connected $\rightarrow$ **OPEN**.
- Non-zero code (e.g., `10061` connection refused on Windows): $\rightarrow$ **CLOSED**.
- `s.close()` is executed immediately to release socket descriptors.

---

## ⚠️ Disclaimer & Ethical Use

This port scanner is intended solely for educational purposes and authorized network testing. Scanning remote networks without permission may violate acceptable use policies and local cyber security laws. Always test on `localhost` (`127.0.0.1`) or designated testing hosts (e.g., `scanme.nmap.org`).
