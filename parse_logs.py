import json
import sqlite3
import requests
import time

# Load and parse the JSON log file (one JSON object per line)
events = []
with open('honeypot-logs.json', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

print(f"Loaded {len(events)} events")

# Set up SQLite database
conn = sqlite3.connect('honeypot.db')
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    eventid TEXT,
    timestamp TEXT,
    src_ip TEXT,
    session TEXT,
    username TEXT,
    password TEXT,
    input TEXT,
    message TEXT
)
''')

c.execute('''
CREATE TABLE IF NOT EXISTS ip_locations (
    src_ip TEXT PRIMARY KEY,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL
)
''')

# Insert all events
for e in events:
    c.execute('''
        INSERT INTO events (eventid, timestamp, src_ip, session, username, password, input, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        e.get('eventid'),
        e.get('timestamp'),
        e.get('src_ip'),
        e.get('session'),
        e.get('username'),
        e.get('password'),
        e.get('input'),
        str(e.get('message'))
    ))

conn.commit()
print("Events inserted into database")

# Get unique IPs and look up their location
c.execute('SELECT DISTINCT src_ip FROM events WHERE src_ip IS NOT NULL')
unique_ips = [row[0] for row in c.fetchall()]
print(f"Found {len(unique_ips)} unique attacker IPs")

for ip in unique_ips:
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = resp.json()
        if data.get('status') == 'success':
            c.execute('''
                INSERT OR REPLACE INTO ip_locations (src_ip, country, city, lat, lon)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip, data.get('country'), data.get('city'), data.get('lat'), data.get('lon')))
            print(f"{ip} -> {data.get('country')}, {data.get('city')}")
        else:
            print(f"{ip} -> lookup failed")
    except Exception as ex:
        print(f"{ip} -> error: {ex}")
    time.sleep(1.5)  # ip-api free tier rate limit: 45 requests/minute

conn.commit()
conn.close()
print("Done! Database saved as honeypot.db")
