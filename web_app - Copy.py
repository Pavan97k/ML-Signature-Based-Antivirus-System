from flask import Flask, render_template, jsonify, request, redirect, url_for
from scanner.database import init_db, get_scans, insert_scan
import os
import random
import shutil

app = Flask(__name__)

# -----------------------------
# INIT DATABASE
# -----------------------------
init_db()

# -----------------------------
# FOLDERS SETUP
# -----------------------------
QUARANTINE_FOLDER = "quarantine_files"
UPLOAD_FOLDER = "uploads"

os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# -----------------------------
# QUARANTINE FUNCTION
# -----------------------------
def quarantine_file(file_path):
    try:
        if not os.path.exists(file_path):
            return False

        file_name = os.path.basename(file_path)
        new_path = os.path.join(QUARANTINE_FOLDER, file_name)

        shutil.move(file_path, new_path)
        print(f"Quarantined: {file_name}")

        return True
    except Exception as e:
        print("Quarantine failed:", e)
        return False


# -----------------------------
# LAST SCAN STORAGE
# -----------------------------
last_scan = {
    "total": 0,
    "malware": 0,
    "benign": 0
}


# -----------------------------
# DASHBOARD
# -----------------------------
@app.route("/")
def dashboard():
    scans = get_scans()

    total = len(scans)
    malware = sum(1 for s in scans if "Malware" in s[2])
    safe = total - malware

    return render_template(
        "dashboard.html",
        scans=scans,
        total=total,
        malware=malware,
        safe=safe,
        last_scan=last_scan
    )


# -----------------------------
# API
# -----------------------------
@app.route("/api/scans")
def api_scans():
    scans = get_scans()

    total = len(scans)
    malware = sum(1 for s in scans if "Malware" in s[2])
    safe = total - malware

    return jsonify({
        "total": total,
        "malware": malware,
        "safe": safe,
        "latest": scans[:5]
    })


# -----------------------------
# SCAN HISTORY
# -----------------------------
@app.route("/scans")
def scans_page():
    scans = get_scans()
    return render_template("scans.html", scans=scans)


# -----------------------------
# QUICK SCAN
# -----------------------------
@app.route("/quick_scan")
def quick_scan():
    global last_scan

    folders = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/AppData/Local/Temp")
    ]

    total = 0
    malware = 0
    benign = 0

    for folder in folders:
        if not os.path.exists(folder):
            continue

        for root, dirs, files in os.walk(folder):

            if QUARANTINE_FOLDER in root:
                continue

            for file in files:
                file_path = os.path.join(root, file)

                try:
                    if file.lower().endswith(".exe"):
                        result = "Malware Detected" if random.random() > 0.4 else "Benign"
                    else:
                        result = "Benign"

                    if "Malware" in result:
                        quarantine_file(file_path)

                    insert_scan(file_path, result)

                    total += 1
                    if "Malware" in result:
                        malware += 1
                    else:
                        benign += 1

                except Exception as e:
                    print("Error scanning:", e)
                    continue

    last_scan = {
        "total": total,
        "malware": malware,
        "benign": benign
    }

    return redirect("/")


# -----------------------------
# FULL SCAN
# -----------------------------
@app.route("/full_scan")
def full_scan():
    global last_scan

    base_path = os.path.expanduser("~")

    total = 0
    malware = 0
    benign = 0

    for root, dirs, files in os.walk(base_path):

        if QUARANTINE_FOLDER in root:
            continue

        for file in files:
            file_path = os.path.join(root, file)

            try:
                if file.lower().endswith(".exe"):
                    result = "Malware Detected" if random.random() > 0.3 else "Benign"
                else:
                    result = "Benign"

                if "Malware" in result:
                    quarantine_file(file_path)

                insert_scan(file_path, result)

                total += 1
                if "Malware" in result:
                    malware += 1
                else:
                    benign += 1

            except Exception as e:
                print("Error scanning:", e)
                continue

    last_scan = {
        "total": total,
        "malware": malware,
        "benign": benign
    }

    return redirect("/")


# -----------------------------
# CUSTOM SCAN
# -----------------------------
@app.route("/customscan", methods=["GET", "POST"])
def customscan():

    if request.method == "POST":

        if "file" not in request.files:
            return "No file uploaded"

        file = request.files["file"]

        if file.filename == "":
            return "No file selected"

        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(file_path)

        if file.filename.lower().endswith(".exe"):
            result = "Malware Detected" if random.random() > 0.3 else "Benign"
        else:
            result = "Benign"

        if "Malware" in result:
            quarantine_file(file_path)

        insert_scan(file.filename, result)

        # 🔥 FIXED HERE
        return redirect("/")

    return render_template("customscan.html")


# -----------------------------
# QUARANTINE PAGE
# -----------------------------
@app.route("/quarantine")
def quarantine():
    files = os.listdir(QUARANTINE_FOLDER)
    return render_template("quarantine.html", files=files)


# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)