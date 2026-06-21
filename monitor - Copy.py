import time
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from scanner.signature_scan import signature_scan
from scanner.feature_extractor import extract_features
from scanner.quarantine import quarantine_file
from ml.predict import predict

from database import init_db, insert_scan


# Folder to monitor
MONITOR_FOLDER = r"C:\Users\anilc\Downloads"

init_db()

recent_scans = set()


# ------------------------------------------------
# Wait until file download is complete
# ------------------------------------------------
def wait_for_download(file_path, timeout=15):

    start_time = time.time()
    last_size = -1

    while time.time() - start_time < timeout:

        if not os.path.exists(file_path):
            time.sleep(1)
            continue

        try:
            current_size = os.path.getsize(file_path)

            if current_size == last_size and current_size > 0:
                return True

            last_size = current_size

        except Exception:
            pass

        time.sleep(1)

    return False


class MalwareMonitor(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        file_path = event.src_path
        filename = os.path.basename(file_path).lower().strip()

        if file_path in recent_scans:
            return

        recent_scans.add(file_path)

        print("\nNew file detected:", file_path)

        # Wait until download completes
        if not wait_for_download(file_path):
            print("File still locked or downloading, skipping:", filename)
            return

        try:

            # Ignore temp download files
            if filename.endswith((".tmp", ".crdownload", ".part")):
                print("Skipping temporary file:", filename)
                return

            # Extract extension
            ext = os.path.splitext(filename)[1]

            executable_extensions = [
                ".exe",
                ".dll",
                ".bat",
                ".scr",
                ".js",
                ".com",
                ".msi",
                ".vbs",
                ".ps1",
                ".zip",
                ".txt",
                ".pdf"
            ]

            if ext not in executable_extensions:
                print("Skipping non-executable file:", filename)
                return

            print("Scanning executable:", filename)

            # Signature scan
            if signature_scan(file_path):

                print("⚠ Malware detected via signature!")

                quarantine_file(file_path)

                insert_scan(file_path, "Malware (Signature)", "High")

                return

            # Demo rule
            if "virus" in filename or "trojan" in filename:

                print("⚠ Demo malware detected!")

                quarantine_file(file_path)

                insert_scan(file_path, "Malware (Demo)", "High")

                return

            # ML scan
            features = extract_features(file_path)

            result = predict(features)

            print(f"Scanning {filename} → {result}")

            if result == "Malware" or result == 1:

                print("⚠ Malware detected by ML!")

                quarantine_file(file_path)

                insert_scan(file_path, "Malware", "Medium")

            else:

                print("✓ File is safe")

                insert_scan(file_path, "Benign", "Low")

        except Exception as e:
            print("Scan error:", e)


# ------------------------------------------------
# Start monitor
# ------------------------------------------------
if __name__ == "__main__":

    event_handler = MalwareMonitor()

    observer = Observer()

    observer.schedule(event_handler, MONITOR_FOLDER, recursive=False)

    observer.start()

    print("Real Time Malware Scanner Started")
    print("Monitoring folder:", MONITOR_FOLDER)

    try:
        while True:
            time.sleep(5)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()