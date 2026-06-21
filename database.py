import sqlite3

def init_db():

    conn = sqlite3.connect("database.db")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file TEXT,
        result TEXT,
        risk TEXT,
        scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def insert_scan(file, result, risk="Low"):

    conn = sqlite3.connect("database.db")

    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO scans(file,result,risk) VALUES(?,?,?)",
        (file,result,risk)
    )

    conn.commit()
    conn.close()


def get_scans():

    conn = sqlite3.connect("database.db")

    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY scan_time DESC")

    scans = cursor.fetchall()

    conn.close()

    return scans