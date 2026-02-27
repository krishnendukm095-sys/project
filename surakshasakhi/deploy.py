"""
SurakshaSakhi - Complete System Deployment Script
Initializes encryption, database, and sample data
Run this ONCE during deployment
"""

import sqlite3
import datetime
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
import json

print("=" * 70)
print("SurakshaSakhi - Complete System Deployment")
print("=" * 70)
print()

# ============ STEP 1: Generate Encryption Key ============
print("[1/4] Generating Encryption Key...")
encryption_key = Fernet.generate_key().decode()
print(f"✓ Key Generated: {encryption_key}\n")

# Save to .env file
print("[2/4] Creating .env Configuration File...")
with open('.env', 'w') as f:
    f.write(f"ENCRYPTION_KEY={encryption_key}\n")
    f.write(f"FLASK_ENV=production\n")
    f.write(f"SECRET_KEY=suraksha_secret_key_2026\n")
print("✓ .env file created\n")

# ============ STEP 2: Initialize Database ============
print("[3/4] Initializing Database with Enhanced Tables...")

conn = sqlite3.connect("database.db")
c = conn.cursor()

# Create all tables
tables_created = []

# 1. Bus Reports Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS bus_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  date TEXT,
                  bus_no TEXT,
                  location TEXT,
                  issue TEXT)''')
    tables_created.append("bus_reports")
except Exception as e:
    print(f"  ! bus_reports: {e}")

# 2. Instant Reports Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS instant_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  issue_type TEXT,
                  description TEXT,
                  location TEXT,
                  anonymous INTEGER,
                  status TEXT DEFAULT 'Pending',
                  timestamp TEXT)''')
    tables_created.append("instant_reports")
except Exception as e:
    print(f"  ! instant_reports: {e}")

# 3. Enhanced Police Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS police
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  full_name TEXT,
                  badge_number TEXT UNIQUE,
                  official_email TEXT,
                  role TEXT DEFAULT 'officer',
                  district TEXT,
                  city TEXT,
                  pin_code TEXT,
                  jurisdiction TEXT,
                  contact_phone TEXT,
                  status TEXT DEFAULT 'Active',
                  created_at TEXT)''')
    tables_created.append("police")
except Exception as e:
    print(f"  ! police: {e}")

# 4. Anonymous Complaints Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS anonymous_complaints
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  report_uuid TEXT UNIQUE NOT NULL,
                  encrypted_data TEXT NOT NULL,
                  district TEXT,
                  city TEXT,
                  pin_code TEXT,
                  incident_date TEXT,
                  submitted_at TEXT,
                  status TEXT DEFAULT 'Pending',
                  assigned_officer_id INTEGER,
                  assigned_at TEXT,
                  FOREIGN KEY (assigned_officer_id) REFERENCES police(id))''')
    tables_created.append("anonymous_complaints")
except Exception as e:
    print(f"  ! anonymous_complaints: {e}")

# 5. Complaint Assignments Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS complaint_assignments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  complaint_id INTEGER NOT NULL,
                  officer_id INTEGER NOT NULL,
                  assigned_at TEXT,
                  acknowledged INTEGER DEFAULT 0,
                  status TEXT DEFAULT 'Assigned',
                  notes TEXT,
                  FOREIGN KEY (complaint_id) REFERENCES anonymous_complaints(id),
                  FOREIGN KEY (officer_id) REFERENCES police(id))''')
    tables_created.append("complaint_assignments")
except Exception as e:
    print(f"  ! complaint_assignments: {e}")

# 6. Journeys Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS journeys
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_phone TEXT,
                  from_location TEXT,
                  to_location TEXT,
                  start_time TEXT,
                  end_time TEXT,
                  status TEXT DEFAULT 'Active',
                  shared_with TEXT,
                  created_at TEXT)''')
    tables_created.append("journeys")
except Exception as e:
    print(f"  ! journeys: {e}")

# 7. Trusted Contacts Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS trusted_contacts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_phone TEXT,
                  contact_name TEXT,
                  contact_phone TEXT,
                  contact_email TEXT,
                  relationship TEXT,
                  trust_level TEXT,
                  status TEXT DEFAULT 'Active',
                  created_at TEXT)''')
    tables_created.append("trusted_contacts")
except Exception as e:
    print(f"  ! trusted_contacts: {e}")

# 8. Incidents Table
try:
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  location TEXT,
                  latitude REAL,
                  longitude REAL,
                  incident_type TEXT,
                  time_of_day TEXT,
                  severity TEXT,
                  timestamp TEXT)''')
    tables_created.append("incidents")
except Exception as e:
    print(f"  ! incidents: {e}")

for table in tables_created:
    print(f"  ✓ {table}")

# ============ STEP 3: Add Sample Police Officers ============
print("\n[4/4] Adding Sample Police Officers with Jurisdiction Info...\n")

sample_officers = [
    {
        'username': 'admin',
        'password': generate_password_hash('password123'),
        'full_name': 'Police Commissioner',
        'badge_number': 'BADGE001',
        'official_email': 'commissioner@police.gov',
        'role': 'admin',
        'district': 'Mumbai Central',
        'city': 'Mumbai',
        'pin_code': '400001',
        'jurisdiction': 'Central District',
        'contact_phone': '9876543210'
    },
    {
        'username': 'officer_central',
        'password': generate_password_hash('password123'),
        'full_name': 'Senior Inspector Priya Singh',
        'badge_number': 'BADGE002',
        'official_email': 'priya.singh@police.gov',
        'role': 'officer',
        'district': 'Mumbai Central',
        'city': 'Mumbai',
        'pin_code': '400001',
        'jurisdiction': 'Central District',
        'contact_phone': '9988776655'
    },
    {
        'username': 'officer_west',
        'password': generate_password_hash('password123'),
        'full_name': 'Inspector Amit Sharma',
        'badge_number': 'BADGE003',
        'official_email': 'amit.sharma@police.gov',
        'role': 'officer',
        'district': 'Mumbai West',
        'city': 'Mumbai',
        'pin_code': '400004',
        'jurisdiction': 'Western District',
        'contact_phone': '9877665544'
    },
    {
        'username': 'officer_south',
        'password': generate_password_hash('password123'),
        'full_name': 'Inspector Neha Desai',
        'badge_number': 'BADGE004',
        'official_email': 'neha.desai@police.gov',
        'role': 'officer',
        'district': 'Mumbai South',
        'city': 'Mumbai',
        'pin_code': '400011',
        'jurisdiction': 'Southern District',
        'contact_phone': '9866554433'
    },
    {
        'username': 'officer_north',
        'password': generate_password_hash('password123'),
        'full_name': 'Inspector Rajesh Patel',
        'badge_number': 'BADGE005',
        'official_email': 'rajesh.patel@police.gov',
        'role': 'officer',
        'district': 'Mumbai North',
        'city': 'Mumbai',
        'pin_code': '400024',
        'jurisdiction': 'Northern District',
        'contact_phone': '9855443322'
    }
]

officers_added = 0
for officer in sample_officers:
    try:
        c.execute("""INSERT INTO police 
                    (username, password, full_name, badge_number, official_email, 
                     role, district, city, pin_code, jurisdiction, contact_phone, created_at) 
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                 (officer['username'], officer['password'], officer['full_name'], 
                  officer['badge_number'], officer['official_email'], officer['role'],
                  officer['district'], officer['city'], officer['pin_code'], 
                  officer['jurisdiction'], officer['contact_phone'], 
                  datetime.datetime.now().isoformat()))
        officers_added += 1
        status = "admin" if officer['role'] == 'admin' else "officer"
        print(f"  ✓ {officer['full_name']} ({status}) - {officer['district']}")
    except sqlite3.IntegrityError:
        print(f"  ⚠ {officer['full_name']} - Already exists")
    except Exception as e:
        print(f"  ✗ {officer['full_name']} - Error: {e}")

conn.commit()
conn.close()

# ============ DEPLOYMENT SUMMARY ============
print("\n" + "=" * 70)
print("DEPLOYMENT SUMMARY")
print("=" * 70)
print()
print("✓ Encryption Key Generated")
print("✓ .env Configuration File Created")
print(f"✓ Database Tables Created: {len(tables_created)}")
print(f"✓ Police Officers Added: {officers_added}")
print()
print("NEXT STEPS:")
print("-" * 70)
print("1. Copy the ENCRYPTION_KEY to your environment variables")
print("2. Update app.py with the encryption key from .env")
print("3. Start Flask app: flask run")
print("4. Visit http://localhost:5000/anonymous_complaint")
print()
print("TEST CREDENTIALS:")
print("-" * 70)
print("Admin Login:")
print("  Username: admin")
print("  Password: password123")
print()
print("Officer Login (Central District):")
print("  Username: officer_central")
print("  Password: password123")
print()
print("=" * 70)
print("Deployment Complete! ✓")
print("=" * 70)
