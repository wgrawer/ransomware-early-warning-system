# 🛡️ Ransomware Detection and Early-Warning System

A real-time behavioral monitoring application designed to detect and alert users of potential ransomware activity on macOS. Built as a capstone project for CSC 455, this system uses OS-level event listeners and velocity heuristics to catch anomalous file modifications instantly.

## 🚀 Features

* **Real-Time File Monitoring:** Leverages Python's `watchdog` library to hook directly into native OS file system events (`FSEvents` on macOS) asynchronously.
* **Velocity-Based Heuristic Detection:** Tracks file modification frequency within a sliding time window (using a timestamp queue/deque) to differentiate rapid encryption behaviors from normal user activity.
* **Responsive GUI:** Built with Python’s `tkinter` running in a multi-threaded architecture to ensure the user interface stays responsive and live-updates alerts without freezing.
* **Persistent Auditing:** Logs all security events, timestamps, and severity labels into a structured `SQLite` database for historical analysis.

---

## 🛠️ Tech Stack

* **Language:** Python 3
* **Libraries:** `watchdog`, `tkinter`, `sqlite3`, `threading`, `collections`
* **Environment:** macOS

---

## ⚙️ Installation & Setup

Follow these steps to set up and run the project locally:

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR-USERNAME/ransomware-early-warning-system.git](https://github.com/YOUR-USERNAME/ransomware-early-warning-system.git)
   cd ransomware-early-warning-system
