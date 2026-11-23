import os
import time
import threading
import sqlite3
from datetime import datetime
from collections import deque
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Ensure the database is always created in the same directory as monitor.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "security_events.db")

def init_db():
    """Initializes the SQLite database and creates the events table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            file_path TEXT,
            severity TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()


def log_to_db(event_type, file_path, severity, details):
    """Inserts a security event or log entry into the SQLite database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_events (timestamp, event_type, file_path, severity, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), event_type, file_path, severity, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")

class RansomwareDetectorApp(FileSystemEventHandler):
    def __init__(self, root, text_widget):
        self.root = root
        self.text_widget = text_widget
        self.modification_times = deque()
        self.threshold = 5     # Max allowed changes before alert
        self.time_window = 3.0 # Time window in seconds

    def log_message(self, message):
        # Safely update the GUI text widget from the background thread using root.after
        self.root.after(0, self._insert_text, message)

    def _insert_text(self, message):
        self.text_widget.config(state='normal')
        self.text_widget.insert(tk.END, message + "\n")
        self.text_widget.see(tk.END) # Auto-scroll to the bottom
        self.text_widget.config(state='disabled')

    def check_anomaly(self, path):
        current_time = time.time()
        self.modification_times.append(current_time)
        
        # Remove timestamps outside the time window
        while self.modification_times and current_time - self.modification_times[0] > self.time_window:
            self.modification_times.popleft()
            
        if len(self.modification_times) > self.threshold:
            # Prevent alert spam by introducing a cooldown between alerts
            if not hasattr(self, 'last_alert_time') or current_time - self.last_alert_time > 2.0:
                alert_msg = f"[!] SECURITY ALERT: Rapid file modifications near {path}!"
                self.log_message(alert_msg)
                log_to_db("ALERT", path, "HIGH", f"Rapid modification burst: {len(self.modification_times)} events in {self.time_window}s.")
                self.last_alert_time = current_time

    def on_modified(self, event):
        if event.is_directory:
            return
        msg = f"File modified -> {event.src_path}"
        self.log_message(msg)
        log_to_db("MODIFIED", event.src_path, "LOW", "Standard file modification.")
        self.check_anomaly(event.src_path)
        
    def on_created(self, event):
        if event.is_directory:
            return
        msg = f"File created -> {event.src_path}"
        self.log_message(msg)
        log_to_db("CREATED", event.src_path, "LOW", "File creation event.")
        self.check_anomaly(event.src_path)

def start_observer(event_handler, path_to_watch):
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except:
        observer.stop()
    observer.join()

def clear_logs(text_widget):
    text_widget.config(state='normal')
    text_widget.delete('1.0', tk.END)
    text_widget.config(state='disabled')

if __name__ == "__main__":
    # Initialize SQLite database file on startup
    init_db()

    # Define the directory path to watch
    path_to_watch = os.path.abspath("./test_folder")
    
    # Ensure the sandbox directory exists
    if not os.path.exists(path_to_watch):
        os.makedirs(path_to_watch)

    # 1. Setup the main Tkinter window
    root = tk.Tk()
    root.title("Ransomware Detector & File Monitor")
    root.geometry("650x450")

    # 2. Add a scrollable text area to display live alerts
    chat_box = ScrolledText(root, state='disabled', width=75, height=20)
    chat_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    # Add a Clear Logs Button
    clear_btn = tk.Button(root, text="Clear Logs", command=lambda: clear_logs(chat_box))
    clear_btn.pack(pady=5)
    
    # 3. Initialize the event handler with references to the GUI
    event_handler = RansomwareDetectorApp(root, chat_box)

    # 4. Start the Watchdog observer in a background thread so the GUI doesn't freeze
    monitor_thread = threading.Thread(target=start_observer, args=(event_handler, path_to_watch), daemon=True)
    monitor_thread.start()

    # Log initial startup message
    event_handler.log_message(f"Starting file monitor on: {path_to_watch}")

    # 5. Run the Tkinter event loop
    root.mainloop()