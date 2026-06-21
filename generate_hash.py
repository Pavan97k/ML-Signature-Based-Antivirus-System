import os
import hashlib
import pandas as pd

MALWARE_FOLDER = "malware"
OUTPUT_FILE = "dataset/malware_hashes.csv"

hashes = []

for filename in os.listdir(MALWARE_FOLDER):

    filepath = os.path.join(MALWARE_FOLDER, filename)

    if os.path.isfile(filepath):

        sha256 = hashlib.sha256()

        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)

        file_hash = sha256.hexdigest()

        hashes.append(file_hash)

        print("Hash generated for:", filename)

df = pd.DataFrame({"hash": hashes})

df.to_csv(OUTPUT_FILE, index=False)

print("Hash database created successfully!")