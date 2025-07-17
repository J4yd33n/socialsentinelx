import sqlite3
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
import sys
import time
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os
import urllib.parse

# Download NLTK data
try:
    nltk.download('vader_lexicon', quiet=True)
except Exception as e:
    print(f"Error downloading NLTK data: {e}")

def init_db():
    """Initialize SQLite database with correct schema."""
    try:
        conn = sqlite3.connect('logs/socialsentinelx.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS campaigns
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, target_email TEXT, 
                      clicked INTEGER, credentials TEXT, key TEXT, sentiment_score REAL, audit_log TEXT)''')
        conn.commit()
        print("Initialized SQLite database: logs/socialsentinelx.db")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

def encrypt_data(data):
    """Encrypt data using AES and return ciphertext and key."""
    try:
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        encrypted = base64.b64encode(nonce + tag + ciphertext).decode()
        return encrypted, base64.b64encode(key).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return "", ""

def decrypt_data(encrypted_data, key):
    """Decrypt AES-encrypted data."""
    try:
        if not encrypted_data or not key:
            return ""
        data = base64.b64decode(encrypted_data)
        key = base64.b64decode(key)
        if len(key) != 16:
            raise ValueError("Invalid AES key length")
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return ""

def run_phishing_campaign(target_email, template="default", report_path="/root/.set/reports/credentials.txt"):
    """Parse SET results from specified report path."""
    audit_log = f"[{time.ctime()}] Initiated phishing campaign for {target_email} with template {template}"
    try:
        # Check for SET report
        credentials = ""
        clicked = 0
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                raw_credentials = f.read().strip()
                # Parse URL-encoded credentials (e.g., username=testuser&password=test123)
                parsed = urllib.parse.parse_qs(raw_credentials)
                credentials = ", ".join(f"{k}: {v[0]}" for k, v in parsed.items()) if parsed else raw_credentials
            clicked = 1 if credentials else 0
        else:
            print(f"No SET report found at {report_path}; configure SET manually with 'sudo setoolkit'.")
            credentials = "username: test, password: test123"  # Simulate for testing
            clicked = 1
        
        # Analyze sentiment
        sia = SentimentIntensityAnalyzer()
        sentiment_score = sia.polarity_scores(credentials or "")['compound']
        
        # Store results with encrypted credentials
        encrypted_creds, key = encrypt_data(credentials)
        conn = sqlite3.connect('logs/socialsentinelx.db')
        c = conn.cursor()
        c.execute("INSERT INTO campaigns (timestamp, target_email, clicked, credentials, key, sentiment_score, audit_log) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (time.time(), target_email, clicked, encrypted_creds, key, sentiment_score, audit_log))
        conn.commit()
        conn.close()
        
        print(f"Phishing campaign processed for {target_email}")
        return {
            "timestamp": time.time(),
            "email": target_email,
            "clicked": clicked,
            "credentials": encrypted_creds,
            "key": key,
            "sentiment_score": sentiment_score,
            "audit_log": audit_log
        }
    except Exception as e:
        print(f"Phishing error: {e}")
        return None

def print_ascii_header():
    """Print ASCII art header for SocialSentinelX."""
    print(r"""
    ____            _       _       ___           _ _       _ _       
   / ___|  ___ _ __| |_ ___| |__   / __|___ _ __ | | | ___ (_) |_ ___ 
   \___ \ / __| '__| __/ __| '_ \ / /  | '_ \| | |/ __|| | __/ __|
    ___) | (__| |  | || (__| | | | \__ | | | | | | (__| | || (__ 
   |____/ \___|_|   \__|\___|_| |_| ___|_| |_|_|_|\___|_|_|\___|

   === SocialSentinelX Ethical Social Engineering ===
    """)

def print_campaign_table(campaign_results):
    """Print a table of campaign results in terminal."""
    if not campaign_results:
        print("\nCampaign Results\nNo campaigns executed.")
        return
    print("\nCampaign Results")
    headers = ["Email", "Clicked", "Credentials", "Sentiment", "Timestamp"]
    print(f"{headers[0]:<20} | {headers[1]:<8} | {headers[2]:<30} | {headers[3]:<10} | {headers[4]}")
    print("-" * 20 + "|" + "-" * 9 + "|" + "-" * 31 + "|" + "-" * 11 + "|" + "-" * 30)
    for result in campaign_results:
        timestamp = time.ctime(result['timestamp'])
        creds = decrypt_data(result['credentials'], result['key']) if result['credentials'] and result['key'] else ""
        print(f"{result['email']:<20} | {'Yes' if result['clicked'] else 'No':<8} | {creds:<30} | {result['sentiment_score']:<10.2f} | {timestamp}")

def show_gui(campaign_results):
    """Show Tkinter GUI dashboard with campaign results and logo."""
    root = tk.Tk()
    root.title("SocialSentinelX Dashboard")
    root.geometry("800x600")
    
    # Add Logo
    try:
        logo_img = Image.open("images/socialsentinelx_logo.png")
        logo_img = logo_img.resize((100, 100), Image.LANCZOS)
        logo_photo = ImageTk.PhotoImage(logo_img)
        tk.Label(root, image=logo_photo).pack(pady=10)
    except Exception as e:
        tk.Label(root, text="SocialSentinelX Dashboard", font=("Arial", 16, "bold")).pack(pady=10)
    
    # Campaign Results Table
    tree = ttk.Treeview(root, columns=("Email", "Clicked", "Credentials", "Sentiment", "Timestamp"), show="headings")
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=150)
    for result in campaign_results:
        creds = decrypt_data(result['credentials'], result['key']) if result['credentials'] and result['key'] else ""
        timestamp = time.ctime(result['timestamp'])
        tree.insert("", "end", values=(
            result["email"], "Yes" if result["clicked"] else "No", creds, f"{result['sentiment_score']:.2f}", timestamp
        ))
    tree.pack(pady=10, fill="both", expand=True)
    
    # Buttons
    tk.Button(root, text="Run Campaign", command=lambda: run_phishing_campaign("test@example.com")).pack(pady=5)
    tk.Button(root, text="Exit", command=sys.exit).pack(pady=5)
    root.mainloop()

def main(use_gui=False):
    """Main function to run SocialSentinelX."""
    init_db()
    campaign_results = []
    
    # Load existing campaigns from database
    try:
        conn = sqlite3.connect('logs/socialsentinelx.db')
        c = conn.cursor()
        c.execute("SELECT timestamp, target_email, clicked, credentials, key, sentiment_score, audit_log FROM campaigns WHERE target_email IS NOT NULL")
        rows = c.fetchall()
        for row in rows:
            campaign_results.append({
                "timestamp": row[0],
                "email": row[1],
                "clicked": row[2],
                "credentials": row[3],
                "key": row[4],
                "sentiment_score": row[5],
                "audit_log": row[6]
            })
        conn.close()
    except sqlite3.Error as e:
        print(f"Database read error: {e}")
    
    # Run a campaign
    result = run_phishing_campaign("test@example.com")
    if result:
        campaign_results.append(result)
    
    if use_gui:
        show_gui(campaign_results)
    else:
        print_ascii_header()
        print_campaign_table(campaign_results)
    
    # Audit log for dashboard access
    audit_log = f"[{time.ctime()}] Dashboard accessed in {'GUI' if use_gui else 'Terminal'} mode"
    try:
        conn = sqlite3.connect('logs/socialsentinelx.db')
        c = conn.cursor()
        c.execute("INSERT INTO campaigns (timestamp, audit_log) VALUES (?, ?)", (time.time(), audit_log))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Audit log error: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SocialSentinelX Ethical Social Engineering")
    parser.add_argument("--gui", action="store_true", help="Run with GUI")
    args = parser.parse_args()
    main(use_gui=args.gui)
