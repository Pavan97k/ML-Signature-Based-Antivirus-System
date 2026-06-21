import hashlib

file_path = "test.exe"

sha256 = hashlib.sha256()

with open(file_path, "rb") as f:
    while chunk := f.read(4096):
        sha256.update(chunk)

file_hash = sha256.hexdigest()

print("Generated Hash:", file_hash)