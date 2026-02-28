from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, Response
import sqlite3
import datetime
import urllib.parse
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from cryptography.fernet import Fernet
import os
import json
from dotenv import load_dotenv
from functools import wraps
import secrets
import re
import csv
import io
import time

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'suraksha_secret_key_2026')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'database.db'))

# ================== ENCRYPTION SETUP ==================
# Load encryption key from .env file
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY not found in .env file. Run deploy script first.")
cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt sensitive complaint data"""
    if isinstance(data, dict):
        data = json.dumps(data)
    if isinstance(data, str):
        data = data.encode()
    return cipher.encrypt(data).decode()

def decrypt_data(encrypted_data):
    """Decrypt sensitive complaint data"""
    try:
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode()
        decrypted = cipher.decrypt(encrypted_data).decode()
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            return decrypted
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

RANK_ORDER = [
    'Constable',
    'Head Constable',
    'Assistant Sub-Inspector',
    'Sub-Inspector',
    'Inspector',
    'Deputy Superintendent',
    'Superintendent',
    'Senior Superintendent',
    'Deputy Inspector General',
    'Inspector General',
    'Additional Director General',
    'Director General',
    'Commissioner'
]
ADMIN_MIN_RANK = 'Superintendent'


def rank_level(rank):
    if not rank:
        return -1
    rank_normalized = rank.strip().lower()
    for idx, item in enumerate(RANK_ORDER):
        if item.lower() == rank_normalized:
            return idx
    return -1


def is_admin_rank(rank):
    return rank_level(rank) >= rank_level(ADMIN_MIN_RANK)


def sanitize_text(value, max_len=500):
    if value is None:
        return ''
    value = str(value).strip()
    value = re.sub(r'[\x00-\x1f\x7f]', ' ', value)
    value = re.sub(r'\s+', ' ', value)
    return value[:max_len]


def get_or_create_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


def validate_csrf():
    token = request.form.get('csrf_token', '')
    session_token = session.get('csrf_token', '')
    return bool(token and session_token and token == session_token)


@app.context_processor
def inject_csrf_token():
    return {'csrf_token': get_or_create_csrf_token}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def execute_write_with_retry(conn, sql, params=(), retries=5, sleep_seconds=0.2):
    for attempt in range(retries):
        try:
            c = conn.cursor()
            c.execute(sql, params)
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if 'database is locked' in str(e).lower() and attempt < retries - 1:
                time.sleep(sleep_seconds * (attempt + 1))
                continue
            raise

# ================== DATABASE SETUP ==================

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    # existing bus reports table
    c.execute('''CREATE TABLE IF NOT EXISTS bus_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  date TEXT,
                  bus_no TEXT,
                  location TEXT,
                  issue TEXT)''')
    # new instant reports table
    c.execute('''CREATE TABLE IF NOT EXISTS instant_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  issue_type TEXT,
                  description TEXT,
                  location TEXT,
                  anonymous INTEGER,
                  status TEXT DEFAULT 'Pending',
                  timestamp TEXT)''')
    
    # Enhanced police officers table with locality information
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
    
    # Anonymous encrypted complaints table
    # include police_station_id for link to selected station
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
                  police_station_id INTEGER,
                  assigned_officer_id INTEGER,
                  assigned_at TEXT,
                  FOREIGN KEY (police_station_id) REFERENCES police_stations(id),
                  FOREIGN KEY (assigned_officer_id) REFERENCES police(id))''')
    
    # Complaint assignment tracking
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
    
    # virtual guardian journeys
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
    # trusted contacts
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
    # heatmap incidents
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  location TEXT,
                  latitude REAL,
                  longitude REAL,
                  incident_type TEXT,
                  time_of_day TEXT,
                  severity TEXT,
                  timestamp TEXT)''')
    
    # Police stations with location details (including contact email)
    c.execute('''CREATE TABLE IF NOT EXISTS police_stations
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  station_name TEXT UNIQUE,
                  address TEXT,
                  district TEXT,
                  city TEXT,
                  pin_code TEXT,
                  latitude REAL,
                  longitude REAL,
                  phone_number TEXT,
                  official_email TEXT,
                  status TEXT DEFAULT 'Active')''')
    
    # Notifications table for police station alerts
    c.execute('''CREATE TABLE IF NOT EXISTS notifications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  complaint_id INTEGER,
                  station_id INTEGER,
                  message TEXT,
                  sent_at TEXT,
                  status TEXT DEFAULT 'Sent',
                  acknowledged INTEGER DEFAULT 0,
                  acknowledged_at TEXT,
                  FOREIGN KEY (complaint_id) REFERENCES anonymous_complaints(id),
                  FOREIGN KEY (station_id) REFERENCES police_stations(id))''')

    # Officers table for location-based complaint management
    c.execute('''CREATE TABLE IF NOT EXISTS police_officers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  full_name TEXT,
                  username TEXT UNIQUE,
                  password TEXT,
                  rank TEXT,
                  district TEXT,
                  city TEXT,
                  pin_code TEXT,
                  locality TEXT)''')

    # Complaints table for dashboard filtering
    c.execute('''CREATE TABLE IF NOT EXISTS complaints
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  report_id TEXT,
                  district TEXT,
                  city TEXT,
                  pin_code TEXT,
                  locality TEXT,
                  issue_category TEXT,
                  complaint_text TEXT,
                  created_at TEXT,
                  assigned_officer_id INTEGER,
                  status TEXT DEFAULT 'pending',
                  FOREIGN KEY (assigned_officer_id) REFERENCES police_officers(id))''')

    # In-app officer notifications
    c.execute('''CREATE TABLE IF NOT EXISTS complaint_notifications
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  officer_id INTEGER NOT NULL,
                  complaint_id INTEGER NOT NULL,
                  message TEXT,
                  is_read INTEGER DEFAULT 0,
                  created_at TEXT,
                  FOREIGN KEY (officer_id) REFERENCES police_officers(id),
                  FOREIGN KEY (complaint_id) REFERENCES complaints(id))''')

    # Auto-generated reports when complaint location maps to officer location
    c.execute('''CREATE TABLE IF NOT EXISTS police_reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  officer_id INTEGER NOT NULL,
                  complaint_id INTEGER NOT NULL,
                  report_text TEXT,
                  created_at TEXT,
                  status TEXT DEFAULT 'new',
                  FOREIGN KEY (officer_id) REFERENCES police_officers(id),
                  FOREIGN KEY (complaint_id) REFERENCES complaints(id))''')

    # Login attempts for rate limiting
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (username TEXT PRIMARY KEY,
                  attempts INTEGER DEFAULT 0,
                  blocked_until TEXT,
                  updated_at TEXT)''')
    
    conn.commit()
    
    # Check if default police user exists, if not create one
    c.execute("SELECT COUNT(*) FROM police")
    if c.fetchone()[0] == 0:
        hashed = generate_password_hash('password123')
        c.execute("""INSERT INTO police 
                    (username, password, full_name, badge_number, official_email, 
                     role, district, city, pin_code, jurisdiction, contact_phone, created_at) 
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                 ('admin', hashed, 'Police Admin', 'BADGE001', 'admin@police.gov',
                  'admin', 'Central', 'Mumbai', '400001', 'Central District', '9876543210', 
                  str(datetime.datetime.now())))

    # Check if default officer exists in police_officers table
    c.execute("SELECT COUNT(*) FROM police_officers WHERE LOWER(username) = LOWER(?)", ('admin',))
    if c.fetchone()[0] == 0:
        c.execute("""INSERT INTO police_officers
                    (full_name, username, password, rank, district, city, pin_code, locality)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                 ('System Admin', 'admin', generate_password_hash('password123'),
                  'Superintendent', 'Central', 'Mumbai', '400001', 'Mumbai'))

    # Migration-safe update for complaints table
    c.execute("PRAGMA table_info(complaints)")
    complaint_cols = [row[1] for row in c.fetchall()]
    if 'assigned_officer_id' not in complaint_cols:
        c.execute("ALTER TABLE complaints ADD COLUMN assigned_officer_id INTEGER")
    if 'status' not in complaint_cols:
        c.execute("ALTER TABLE complaints ADD COLUMN status TEXT DEFAULT 'pending'")
    if 'locality' not in complaint_cols:
        c.execute("ALTER TABLE complaints ADD COLUMN locality TEXT")
    if 'issue_category' not in complaint_cols:
        c.execute("ALTER TABLE complaints ADD COLUMN issue_category TEXT")
    c.execute("UPDATE complaints SET status = 'pending' WHERE status IS NULL OR TRIM(status) = ''")
    c.execute("UPDATE complaints SET issue_category = 'Other' WHERE issue_category IS NULL OR TRIM(issue_category) = ''")
    c.execute("UPDATE complaints SET locality = city WHERE locality IS NULL OR TRIM(locality) = ''")

    c.execute("PRAGMA table_info(police_officers)")
    officer_cols = [row[1] for row in c.fetchall()]
    if 'locality' not in officer_cols:
        c.execute("ALTER TABLE police_officers ADD COLUMN locality TEXT")
    c.execute("UPDATE police_officers SET locality = city WHERE locality IS NULL OR TRIM(locality) = ''")

    # Backfill dashboard complaints from legacy anonymous_complaints records
    c.execute("""INSERT INTO complaints (report_id, district, city, pin_code, locality, issue_category, complaint_text, created_at, status)
                 SELECT ac.report_uuid, ac.district, ac.city, ac.pin_code,
                        ac.city,
                        'Other',
                        'Encrypted complaint submitted',
                        COALESCE(ac.submitted_at, ?),
                        CASE LOWER(COALESCE(ac.status, 'pending'))
                            WHEN 'resolved' THEN 'resolved'
                            WHEN 'assigned' THEN 'assigned'
                            WHEN 'in progress' THEN 'assigned'
                            ELSE 'pending'
                        END
                 FROM anonymous_complaints ac
                 WHERE NOT EXISTS (
                    SELECT 1 FROM complaints c2 WHERE c2.report_id = ac.report_uuid
                 )""", (datetime.datetime.now().isoformat(),))
    
    # Insert sample police stations with location data
    c.execute("SELECT COUNT(*) FROM police_stations")
    if c.fetchone()[0] == 0:
        sample_stations = [
            ('Central Station', '123 Main Road, Fort', 'Mumbai Central', 'Mumbai', '400001', 18.9547, 72.8258, '9876543210','central@police.gov'),
            ('Western Suburbs Station', '456 Western Express Hwy', 'Mumbai West', 'Mumbai', '400004', 19.1136, 72.8697, '9876543211','west@police.gov'),
            ('Southern Station', '789 South Mumbai Avenue', 'Mumbai South', 'Mumbai', '400011', 18.9676, 72.8194, '9876543212','south@police.gov'),
            ('Northern Station', '321 North Avenue', 'Mumbai North', 'Mumbai', '400024', 19.2183, 72.9781, '9876543213','north@police.gov'),
            ('Eastern Station', '654 Eastern Region Road', 'Mumbai East', 'Mumbai', '400014', 19.0976, 72.8988, '9876543214','east@police.gov'),
        ]
        for station in sample_stations:
            c.execute("""INSERT OR IGNORE INTO police_stations 
                        (station_name, address, district, city, pin_code, latitude, longitude, phone_number, official_email)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", station)
    
    conn.commit()
    conn.close()

init_db()


def is_login_blocked(conn, username):
    c = conn.cursor()
    c.execute("SELECT attempts, blocked_until FROM login_attempts WHERE LOWER(username) = LOWER(?)", (username,))
    row = c.fetchone()
    if not row:
        return False, None
    blocked_until = row[1]
    if not blocked_until:
        return False, None
    try:
        blocked_dt = datetime.datetime.fromisoformat(blocked_until)
        now = datetime.datetime.now()
        if blocked_dt > now:
            return True, blocked_dt
    except ValueError:
        return False, None
    return False, None


def record_login_failure(conn, username):
    c = conn.cursor()
    now = datetime.datetime.now()
    c.execute("SELECT attempts FROM login_attempts WHERE LOWER(username) = LOWER(?)", (username,))
    row = c.fetchone()
    attempts = (row[0] if row else 0) + 1
    blocked_until = None
    if attempts >= 3:
        blocked_until = (now + datetime.timedelta(minutes=15)).isoformat()
        attempts = 0
    execute_write_with_retry(
        conn,
        """INSERT INTO login_attempts (username, attempts, blocked_until, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET
              attempts = excluded.attempts,
              blocked_until = excluded.blocked_until,
              updated_at = excluded.updated_at""",
        (username, attempts, blocked_until, now.isoformat())
    )


def clear_login_attempts(conn, username):
    execute_write_with_retry(conn, "DELETE FROM login_attempts WHERE LOWER(username) = LOWER(?)", (username,))

# ---------------- HOME ----------------

@app.route('/')
def home():
    return render_template('home.html')

# ---------------- INSTANT SAFETY REPORT ----------------

@app.route('/instant_report', methods=['GET', 'POST'])
def instant_report():
    confirmation = None
    if request.method == 'POST':
        issue_type = request.form.get('issue_type')
        description = request.form.get('description')
        location = request.form.get('location') or 'Unknown'
        anonymous = 1 if request.form.get('anonymous') == 'on' else 0
        timestamp = str(datetime.datetime.now())

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO instant_reports (issue_type, description, location, anonymous, timestamp) VALUES (?,?,?,?,?)",
                  (issue_type, description, location, anonymous, timestamp))
        conn.commit()
        report_id = c.lastrowid
        conn.close()

        confirmation = f"Report submitted successfully. Your Report ID is {report_id}."
    return render_template('instant_report.html', confirmation=confirmation)

# ================== ANONYMOUS SECURE COMPLAINT SUBMISSION ==================

def find_jurisdiction_officers(district, city):
    """Find police officers in the same jurisdiction"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # First try exact match with district and city
    c.execute("""SELECT id, full_name, badge_number, official_email, contact_phone 
                FROM police 
                WHERE (district = ? OR jurisdiction = ?) 
                AND status = 'Active'
                LIMIT 5""", (district, city))
    
    officers = c.fetchall()
    conn.close()
    
    return officers if officers else []

def find_nearby_police_stations(district, city, pin_code):
    """Find nearby police stations based on location (district, city, or PIN)"""
    conn = get_db_connection()
    c = conn.cursor()
    
    stations = []
    
    # Priority 1: Exact PIN code match
    if pin_code:
        c.execute("""SELECT id, station_name, address, district, city, pin_code, 
                            phone_number, official_email, latitude, longitude
                     FROM police_stations
                     WHERE pin_code = ? AND status = 'Active'
                     ORDER BY station_name""", (pin_code,))
        stations = c.fetchall()
    
    # Priority 2: Exact district match
    if not stations and district:
        c.execute("""SELECT id, station_name, address, district, city, pin_code, 
                            phone_number, official_email, latitude, longitude
                     FROM police_stations
                     WHERE district = ? AND status = 'Active'
                     ORDER BY station_name""", (district,))
        stations = c.fetchall()
    
    # Priority 3: City match
    if not stations and city:
        c.execute("""SELECT id, station_name, address, district, city, pin_code, 
                            phone_number, official_email, latitude, longitude
                     FROM police_stations
                     WHERE city = ? AND status = 'Active'
                     ORDER BY station_name""", (city,))
        stations = c.fetchall()
    
    # Get officers for each station
    stations_with_officers = []
    for station in stations:
        station_id = station[0]
        station_district = station[3]
        
        # Get officers assigned to this station's district
        c.execute("""SELECT id, full_name, contact_phone, official_email, badge_number, username
                     FROM police
                     WHERE district = ? AND role = 'officer'
                     LIMIT 3""", (station_district,))
        
        officers_rows = c.fetchall()
        officer_list = []
        for officer in officers_rows:
            officer_list.append({
                'id': officer[0],
                'full_name': officer[1],
                'contact_phone': officer[2],
                'official_email': officer[3],
                'badge_number': officer[4],
                'username': officer[5]
            })
        
        stations_with_officers.append({
            'station': list(station),
            'officers': officer_list
        })
    
    conn.close()
    return stations_with_officers

@app.route('/anonymous_complaint', methods=['GET', 'POST'])
def anonymous_complaint():
    """Secure anonymous complaint submission with encryption"""
    confirmation = None
    report_uuid = None
    
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid request token. Please retry.', 'danger')
            return redirect(url_for('anonymous_complaint'))

        # Collect complaint data
        district = sanitize_text(request.form.get('district', ''), 100)
        city = sanitize_text(request.form.get('city', ''), 100)
        pin_code = sanitize_text(request.form.get('pin_code', ''), 20)
        locality = sanitize_text(request.form.get('locality', ''), 100)
        incident_date = request.form.get('incident_date', '')
        description = sanitize_text(request.form.get('description', ''), 2000)
        issue_category = sanitize_text(request.form.get('issue_category', 'General'), 50)
        selected_station_id = request.form.get('selected_station_id', None)

        if not locality:
            flash('Locality is required.', 'danger')
            return redirect(url_for('anonymous_complaint'))
        if not issue_category:
            flash('Issue category is required.', 'danger')
            return redirect(url_for('anonymous_complaint'))
        
        # Optional evidence/attachment handling
        evidence_file = request.files.get('evidence_file')
        evidence_filename = None
        
        if evidence_file and evidence_file.filename:
            # Store file securely with encrypted filename
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            evidence_filename = f"evidence_{timestamp}_{uuid.uuid4().hex[:8]}"
        
        # Prepare complaint data for encryption
        complaint_data = {
            'issue_category': issue_category,
            'description': description,
            'evidence_file': evidence_filename,
            'submitted_at': datetime.datetime.now().isoformat()
        }
        
        # Encrypt sensitive complaint data
        encrypted_data = encrypt_data(complaint_data)
        
        # Generate unique UUID-based report ID
        report_uuid = str(uuid.uuid4())
        submitted_at = datetime.datetime.now().isoformat()
        
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Store encrypted complaint (no PII stored in plain text)
            # include chosen station id if provided
            fields = ["report_uuid","encrypted_data","district","city","pin_code",
                      "incident_date","submitted_at","status"]
            vals   = [report_uuid, encrypted_data, district, city, pin_code,
                      incident_date, submitted_at, 'Pending']
            if selected_station_id:
                fields.insert(7,"police_station_id")
                vals.insert(7, selected_station_id)

            sql = f"INSERT INTO anonymous_complaints ({', '.join(fields)}) VALUES ({', '.join(['?']*len(fields))})"
            c.execute(sql, tuple(vals))
            complaint_id = c.lastrowid

            # Store searchable complaint metadata for officer dashboard
            c.execute("""INSERT INTO complaints
                        (report_id, district, city, pin_code, locality, issue_category, complaint_text, created_at, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (report_uuid, district, city, pin_code, locality, issue_category, description, submitted_at, 'pending'))
            dashboard_complaint_id = c.lastrowid

            # Create in-app notifications for officers mapped by location
            if locality:
                c.execute("""SELECT id FROM police_officers
                             WHERE LOWER(locality) = LOWER(?)""", (locality,))
            elif pin_code:
                c.execute("""SELECT id FROM police_officers
                             WHERE LOWER(pin_code) = LOWER(?)""", (pin_code,))
            elif city:
                c.execute("""SELECT id FROM police_officers
                             WHERE LOWER(city) = LOWER(?)""", (city,))
            else:
                c.execute("""SELECT id FROM police_officers
                             WHERE LOWER(district) = LOWER(?)""", (district,))
            officer_ids = [row[0] for row in c.fetchall()]
            notify_message = f"New complaint {report_uuid} reported in your area."
            for officer_id in officer_ids:
                c.execute("""INSERT INTO complaint_notifications
                             (officer_id, complaint_id, message, is_read, created_at)
                             VALUES (?, ?, ?, 0, ?)""",
                          (officer_id, dashboard_complaint_id, notify_message, submitted_at))
                c.execute("""INSERT INTO police_reports
                             (officer_id, complaint_id, report_text, created_at, status)
                             VALUES (?, ?, ?, ?, 'new')""",
                          (officer_id, dashboard_complaint_id,
                           f"Mapped report generated for complaint {report_uuid} at {city or district}.",
                           submitted_at))
            conn.commit()
            
            # Find officers in jurisdiction and assign
            officers = find_jurisdiction_officers(district, city)
            
            if officers:
                # Assign to first available officer (in production: use load balancing)
                assigned_officer_id = officers[0][0]
                assigned_at = datetime.datetime.now().isoformat()
                
                c.execute("""UPDATE anonymous_complaints 
                            SET assigned_officer_id = ?, assigned_at = ?, status = 'Assigned'
                            WHERE id = ?""",
                         (assigned_officer_id, assigned_at, complaint_id))
                
                # Log assignment
                c.execute("""INSERT INTO complaint_assignments 
                            (complaint_id, officer_id, assigned_at, status)
                            VALUES (?, ?, ?, ?)""",
                         (complaint_id, assigned_officer_id, assigned_at, 'Assigned'))
                
                conn.commit()
            
            conn.close()
            
            confirmation = f"""
            ✓ Your anonymous complaint has been submitted securely.
            
            Report ID: {report_uuid}
            
            Keep this ID safe for future reference. Your complaint has been encrypted 
            and your identity is completely protected.
            """
            
        except Exception as e:
            flash(f'Error submitting complaint: {str(e)}', 'danger')
            report_uuid = None
    
    return render_template('anonymous_complaint.html', 
                         confirmation=confirmation, 
                         report_uuid=report_uuid)

# ================== POLICE COMPLAINT MANAGEMENT ==================

@app.route('/police/complaints', methods=['GET'])
def police_complaints():
    """View assigned complaints for logged-in officer"""
    if not session.get('police_logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get logged-in officer's ID
    username = session.get('police_user')
    c.execute("SELECT id FROM police WHERE username = ?", (username,))
    officer = c.fetchone()
    
    if not officer:
        flash('Officer not found', 'danger')
        return redirect(url_for('login'))
    
    officer_id = officer[0]
    
    # Get all complaints assigned to this officer
    c.execute("""SELECT ac.id, ac.report_uuid, ac.district, ac.city, 
                        ac.pin_code, ac.incident_date, ac.submitted_at, 
                        ac.status, ca.acknowledged
                FROM anonymous_complaints ac
                LEFT JOIN complaint_assignments ca ON ac.id = ca.complaint_id
                WHERE ac.assigned_officer_id = ? OR ca.officer_id = ?
                ORDER BY ac.submitted_at DESC""",
             (officer_id, officer_id))
    
    complaints = c.fetchall()
    conn.close()
    
    # NOTE: Decryption happens on-demand when officer views specific complaint
    return render_template('police_complaints.html', complaints=complaints)

@app.route('/police/complaint/<complaint_uuid>', methods=['GET', 'POST'])
def view_complaint_details(complaint_uuid):
    """View encrypted complaint details (officer only)"""
    if not session.get('police_logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Verify officer is assigned to this complaint
    c.execute("""SELECT ac.id, ac.encrypted_data 
                FROM anonymous_complaints ac
                WHERE ac.report_uuid = ?""", (complaint_uuid,))
    
    result = c.fetchone()
    
    if not result:
        flash('Complaint not found', 'danger')
        conn.close()
        return redirect(url_for('police_complaints'))
    
    complaint_id, encrypted_data = result
    
    # Verify assignment
    username = session.get('police_user')
    c.execute("""SELECT id FROM police WHERE username = ?""", (username,))
    officer = c.fetchone()
    officer_id = officer[0] if officer else None
    
    c.execute("""SELECT officer_id FROM complaint_assignments 
                WHERE complaint_id = ? AND officer_id = ?""",
             (complaint_id, officer_id))
    
    if not c.fetchone():
        flash('You are not assigned to this complaint', 'danger')
        conn.close()
        return redirect(url_for('police_complaints'))
    
    # Decrypt complaint data
    complaint_data = decrypt_data(encrypted_data)
    
    if request.method == 'POST':
        # Officer updates status
        new_status = request.form.get('status', 'Pending')
        notes = request.form.get('notes', '')
        
        c.execute("""UPDATE anonymous_complaints 
                    SET status = ? WHERE id = ?""",
                 (new_status, complaint_id))
        
        c.execute("""UPDATE complaint_assignments 
                    SET status = ?, notes = ?, acknowledged = 1
                    WHERE complaint_id = ? AND officer_id = ?""",
                 (new_status, notes, complaint_id, officer_id))
        
        conn.commit()
        flash('Complaint status updated', 'success')
    
    conn.close()
    
    return render_template('complaint_details.html', 
                         report_uuid=complaint_uuid,
                         complaint_data=complaint_data)

# ================== POLICE STATION NOTIFICATION ==================

@app.route('/notify_police_station/<int:station_id>/<int:complaint_id>', methods=['POST'])
def notify_police_station(station_id, complaint_id):
    """Notify a police station about a complaint"""
    if not session.get('user_logged_in'):
        return {'status': 'error', 'message': 'Unauthorized'}, 401
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        # Get station details
        c.execute("""SELECT station_name, phone_number, address 
                    FROM police_stations WHERE id = ?""", (station_id,))
        station = c.fetchone()
        
        if not station:
            return {'status': 'error', 'message': 'Station not found'}, 404
        
        # Get complaint details
        c.execute("""SELECT report_uuid, district, city, pin_code, incident_date,
                           encrypted_data
                    FROM anonymous_complaints WHERE id = ?""", (complaint_id,))
        complaint = c.fetchone()
        
        if not complaint:
            return {'status': 'error', 'message': 'Complaint not found'}, 404
        
        report_uuid, district, city, pin_code, incident_date, encrypted_data = complaint
        
        # Decrypt to get category
        complaint_data = decrypt_data(encrypted_data)
        issue_category = complaint_data.get('issue_category', 'General') if complaint_data else 'General'
        
        # Create notification record
        notification_message = f"""
POLICE NOTIFICATION ALERT 🚔
=====================================
Station: {station[0]}
Report ID: {report_uuid}
Category: {issue_category}
Location: {district}, {city} ({pin_code})
Date: {incident_date}
Contact: {station[1]}
Address: {station[2]}
=====================================
"""
        
        # In production, send SMS/Email/WhatsApp notification
        # For now, just log the notification
        c.execute("""INSERT INTO notifications (complaint_id, station_id, message, sent_at, status)
                    VALUES (?, ?, ?, ?, ?)""",
                 (complaint_id, station_id, notification_message, 
                  datetime.datetime.now().isoformat(), 'Sent'))
        
        conn.commit()
        conn.close()
        
        return {'status': 'success', 'message': f'Notification sent to {station[0]}'}, 200
        
    except Exception as e:
        return {'status': 'error', 'message': str(e)}, 500

# ================== API: NEARBY POLICE STATIONS ==================

@app.route('/api/nearby_stations', methods=['POST'])
def api_nearby_stations():
    """API endpoint to fetch nearby police stations based on location with officers"""
    try:
        data = request.get_json()
        district = data.get('district', '').strip()
        city = data.get('city', '').strip()
        pin_code = data.get('pin_code', '').strip()
        
        # PIN code is optional but preferred for search
        # Find nearby police stations (with associated officers)
        stations_data = find_nearby_police_stations(district, city, pin_code)
        
        if not stations_data:
            return {'stations': [], 'officers': []}, 200
        
        return {'stations_data': stations_data}, 200
        
    except Exception as e:
        return {'error': str(e)}, 500

# ================== BUS SOS SYSTEM ================

@app.route('/bus_sos', methods=['GET', 'POST'])
def bus_sos():
    police_whatsapp_link = None
    conductor_message = None
    maps_link = None

    if request.method == 'POST':
        bus_no = request.form['bus']
        location = request.form['location']
        issue = request.form['issue']
        date = str(datetime.datetime.now())

        # Save report in database
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO bus_reports (date, bus_no, location, issue) VALUES (?, ?, ?, ?)",
                  (date, bus_no, location, issue))
        conn.commit()
        conn.close()

        # Create emergency message
        message = f"""
EMERGENCY ALERT 🚨

I am feeling unsafe in Bus No: {bus_no}
Location: {location}

Issue: {issue}

Please provide immediate assistance.
        """

        encoded_message = urllib.parse.quote(message)

        # WhatsApp police (use correct number later)
        police_whatsapp_link = f"https://wa.me/911?text={encoded_message}"

        # Google Maps link
        maps_link = f"https://www.google.com/maps/search/{urllib.parse.quote(location)}"

        # Message to show conductor
        conductor_message = message

    return render_template("bus_sos.html",
                           police_whatsapp_link=police_whatsapp_link,
                           conductor_message=conductor_message,
                           maps_link=maps_link)

# ---------------- LOGIN ----------------

@app.route('/login', methods=['GET'])
def login():
    # genel login page offering choice
    return render_template('login.html')

@app.route('/login/police', methods=['GET','POST'])
@app.route('/police_login', methods=['GET','POST'])
def login_police():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid request token. Please retry.', 'danger')
            return render_template('police_login.html')

        username = sanitize_text(request.form.get('username', ''), 60)
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('police_login.html')

        conn = get_db_connection()
        c = conn.cursor()
        blocked, blocked_until = is_login_blocked(conn, username)
        if blocked:
            conn.close()
            flash(f'Too many failed attempts. Try again after {blocked_until.strftime("%H:%M:%S")}.', 'danger')
            return render_template('police_login.html')

        c.execute("""SELECT id, full_name, username, password, rank, district, city, pin_code, locality
                     FROM police_officers
                     WHERE LOWER(username) = LOWER(?)""", (username,))
        officer = c.fetchone()

        if officer and check_password_hash(officer[3], password):
            clear_login_attempts(conn, username)
            conn.close()
            session.clear()
            session['police_logged_in'] = True
            session['officer_id'] = officer[0]
            session['police_user'] = officer[2]
            session['officer_name'] = officer[1]
            session['police_rank'] = officer[4] or ''
            session['officer_district'] = officer[5] or ''
            session['officer_city'] = officer[6] or ''
            session['officer_pin_code'] = officer[7] or ''
            session['officer_locality'] = officer[8] or ''
            session['police_is_admin'] = is_admin_rank(officer[4]) or (officer[2].lower() == 'admin')
            get_or_create_csrf_token()
            flash('Login successful', 'success')
            return redirect(url_for('dashboard_police'))

        record_login_failure(conn, username)
        conn.close()
        flash('Invalid username or password', 'danger')

    return render_template('police_login.html')

@app.route('/login/officer', methods=['GET','POST'])
def login_officer():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT password FROM police WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session['officer_logged_in'] = True
            session['officer_user'] = username
            return redirect(url_for('dashboard_officer'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login_officer.html')

# ---------------- DASHBOARDS ----------------

def police_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('police_logged_in') or not session.get('officer_id'):
            return redirect(url_for('login_police'))
        return f(*args, **kwargs)
    return wrapper


def officer_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('officer_logged_in'):
            return redirect(url_for('login_officer'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('police_logged_in') or not session.get('police_is_admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('login_police'))
        return f(*args, **kwargs)
    return wrapper


def get_current_officer_row():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""SELECT id, full_name, username, rank, district, city, pin_code, locality
                 FROM police_officers
                 WHERE id = ?""", (session.get('officer_id'),))
    officer = c.fetchone()
    conn.close()
    return officer


def get_officer_scope_clause(officer):
    """Build location scope filter for non-admin officers.
    Priority:
    1) exact pin_code
    2) exact city
    3) exact district
    Always includes assigned complaints.
    """
    officer_id = officer[0]
    district = sanitize_text(officer[4] or '', 100)
    city = sanitize_text(officer[5] or '', 100)
    pin_code = sanitize_text(officer[6] or '', 20)
    locality = sanitize_text(officer[7] or '', 100)

    # Strict locality matching first as requested.
    if locality:
        return "(LOWER(c.locality) = LOWER(?) OR c.assigned_officer_id = ?)", [locality, officer_id]

    if pin_code:
        return "(LOWER(c.pin_code) = LOWER(?) OR c.assigned_officer_id = ?)", [pin_code, officer_id]
    if city:
        return "(LOWER(c.city) = LOWER(?) OR c.assigned_officer_id = ?)", [city, officer_id]
    if district:
        return "(LOWER(c.district) = LOWER(?) OR c.assigned_officer_id = ?)", [district, officer_id]
    return "(c.assigned_officer_id = ?)", [officer_id]


def build_complaint_filter(officer, is_admin_user, args):
    where_parts = []
    params = []

    if not is_admin_user:
        scope_sql, scope_params = get_officer_scope_clause(officer)
        where_parts.append(scope_sql)
        params.extend(scope_params)

    districts = [sanitize_text(v, 100) for v in args.getlist('district') if sanitize_text(v, 100)]
    if districts:
        where_parts.append("(" + " OR ".join(["LOWER(c.district) = LOWER(?)"] * len(districts)) + ")")
        params.extend(districts)

    cities = [sanitize_text(v, 100) for v in args.getlist('city') if sanitize_text(v, 100)]
    if cities:
        where_parts.append("(" + " OR ".join(["LOWER(c.city) = LOWER(?)"] * len(cities)) + ")")
        params.extend(cities)

    pin_codes = [sanitize_text(v, 20) for v in args.getlist('pin_code') if sanitize_text(v, 20)]
    if pin_codes:
        where_parts.append("(" + " OR ".join(["LOWER(c.pin_code) = LOWER(?)"] * len(pin_codes)) + ")")
        params.extend(pin_codes)

    statuses = [sanitize_text(v, 20).lower() for v in args.getlist('status') if sanitize_text(v, 20)]
    if statuses:
        where_parts.append("(" + " OR ".join(["LOWER(COALESCE(c.status,'pending')) = ?"] * len(statuses)) + ")")
        params.extend(statuses)

    from_date = sanitize_text(args.get('from_date', ''), 20)
    to_date = sanitize_text(args.get('to_date', ''), 20)
    if from_date:
        where_parts.append("date(c.created_at) >= date(?)")
        params.append(from_date)
    if to_date:
        where_parts.append("date(c.created_at) <= date(?)")
        params.append(to_date)

    q = sanitize_text(args.get('q', ''), 150)
    if q:
        where_parts.append("(LOWER(c.report_id) LIKE LOWER(?) OR LOWER(c.complaint_text) LIKE LOWER(?))")
        params.extend([f"%{q}%", f"%{q}%"])

    where_sql = " WHERE " + " AND ".join(where_parts) if where_parts else ""
    return where_sql, params, q, from_date, to_date, districts, cities, pin_codes, statuses


@app.route('/police_register', methods=['GET', 'POST'])
def police_register():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid request token. Please retry.', 'danger')
            return redirect(url_for('police_register'))

        full_name = sanitize_text(request.form.get('full_name', ''), 120)
        username = sanitize_text(request.form.get('username', ''), 60)
        password = request.form.get('password', '')
        rank = sanitize_text(request.form.get('rank', ''), 80)
        district = sanitize_text(request.form.get('district', ''), 100)
        city = sanitize_text(request.form.get('city', ''), 100)
        pin_code = sanitize_text(request.form.get('pin_code', ''), 20)
        locality = sanitize_text(request.form.get('locality', ''), 100)

        if not all([full_name, username, password, rank, district, city, pin_code, locality]):
            flash('All fields are required.', 'danger')
            return render_template('police_register.html')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,60}', username):
            flash('Username must be 3-60 chars and contain only letters, numbers, dot, underscore, hyphen.', 'danger')
            return render_template('police_register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('police_register.html')

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""INSERT INTO police_officers
                         (full_name, username, password, rank, district, city, pin_code, locality)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                      (full_name, username, generate_password_hash(password), rank, district, city, pin_code, locality))
            conn.commit()
            conn.close()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login_police'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        except Exception as e:
            flash(f'Failed to register: {str(e)}', 'danger')

    return render_template('police_register.html')


@app.route('/police_profile', methods=['GET', 'POST'])
@police_required
def police_profile():
    officer = get_current_officer_row()
    if not officer:
        session.clear()
        flash('Session expired. Please login again.', 'danger')
        return redirect(url_for('login_police'))

    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid request token. Please retry.', 'danger')
            return redirect(url_for('police_profile'))

        full_name = sanitize_text(request.form.get('full_name', ''), 120)
        rank = sanitize_text(request.form.get('rank', ''), 80)
        district = sanitize_text(request.form.get('district', ''), 100)
        city = sanitize_text(request.form.get('city', ''), 100)
        pin_code = sanitize_text(request.form.get('pin_code', ''), 20)
        locality = sanitize_text(request.form.get('locality', ''), 100)

        if not all([full_name, rank, district, city, pin_code, locality]):
            flash('All fields are required.', 'danger')
            return render_template('police_profile.html', officer=officer)

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""UPDATE police_officers
                     SET full_name = ?, rank = ?, district = ?, city = ?, pin_code = ?, locality = ?
                     WHERE id = ?""",
                  (full_name, rank, district, city, pin_code, locality, officer[0]))
        conn.commit()
        conn.close()

        session['officer_name'] = full_name
        session['police_rank'] = rank
        session['officer_district'] = district
        session['officer_city'] = city
        session['officer_pin_code'] = pin_code
        session['officer_locality'] = locality
        session['police_is_admin'] = is_admin_rank(rank) or (session.get('police_user', '').lower() == 'admin')

        flash('Profile and location updated successfully.', 'success')
        return redirect(url_for('dashboard_police'))

    return render_template('police_profile.html', officer=officer)

@app.route('/create_officer', methods=['GET', 'POST'])
@admin_required
def create_officer():
    if request.method == 'POST':
        if not validate_csrf():
            flash('Invalid request token. Please retry.', 'danger')
            return redirect(url_for('create_officer'))

        full_name = sanitize_text(request.form.get('full_name', ''), 120)
        username = sanitize_text(request.form.get('username', ''), 60)
        password = request.form.get('password', '')
        rank = sanitize_text(request.form.get('rank', ''), 80)
        district = sanitize_text(request.form.get('district', ''), 100)
        city = sanitize_text(request.form.get('city', ''), 100)
        pin_code = sanitize_text(request.form.get('pin_code', ''), 20)
        locality = sanitize_text(request.form.get('locality', ''), 100)

        if not all([full_name, username, password, rank, district, city, pin_code, locality]):
            flash('All fields are required', 'danger')
            return render_template('create_officer.html')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,60}', username):
            flash('Username must be 3-60 chars and contain only letters, numbers, dot, underscore, hyphen.', 'danger')
            return render_template('create_officer.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('create_officer.html')

        hashed_password = generate_password_hash(password)
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("""INSERT INTO police_officers
                         (full_name, username, password, rank, district, city, pin_code, locality)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                      (full_name, username, hashed_password, rank, district, city, pin_code, locality))
            conn.commit()
            conn.close()
            flash('Officer created successfully', 'success')
            return redirect(url_for('create_officer'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        except Exception as e:
            flash(f'Failed to create officer: {str(e)}', 'danger')

    return render_template('create_officer.html')

@app.route('/dashboard/police')
@app.route('/police_dashboard')
@police_required
def dashboard_police():
    page = request.args.get('page', 1, type=int)
    page = page if page and page > 0 else 1
    per_page = 10

    officer = get_current_officer_row()
    if not officer:
        session.clear()
        flash('Session expired. Please login again.', 'danger')
        return redirect(url_for('login_police'))

    is_admin_user = bool(session.get('police_is_admin'))
    conn = get_db_connection()
    c = conn.cursor()
    where_sql, params, q, from_date, to_date, districts, cities, pin_codes, statuses = build_complaint_filter(officer, is_admin_user, request.args)

    c.execute("SELECT COUNT(*) FROM complaints c" + where_sql, params)
    total_count = c.fetchone()[0]
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    offset = (page - 1) * per_page

    c.execute("""SELECT c.id, c.report_id, c.district, c.city, c.pin_code, c.locality, c.issue_category, c.complaint_text, c.created_at,
                        LOWER(COALESCE(c.status,'pending')) AS status, c.assigned_officer_id, po.full_name
                 FROM complaints c
                 LEFT JOIN police_officers po ON po.id = c.assigned_officer_id
              """ + where_sql + " ORDER BY c.id DESC LIMIT ? OFFSET ?", params + [per_page, offset])
    complaints = c.fetchall()

    assignment_options = {}
    for row in complaints:
        c.execute("""SELECT id, full_name, rank
                     FROM police_officers
                     WHERE LOWER(locality) = LOWER(?)
                        OR LOWER(district) = LOWER(?) OR LOWER(city) = LOWER(?)
                     ORDER BY full_name""", (row[5] or '', row[2] or '', row[3] or ''))
        assignment_options[row[0]] = c.fetchall()

    c.execute("SELECT COUNT(*) FROM complaint_notifications WHERE officer_id = ? AND is_read = 0", (officer[0],))
    unread_count = c.fetchone()[0]
    c.execute("""SELECT id, report_text, created_at, status
                 FROM police_reports
                 WHERE officer_id = ?
                 ORDER BY id DESC
                 LIMIT 5""", (officer[0],))
    generated_reports = c.fetchall()

    c.execute("SELECT DISTINCT district FROM complaints WHERE district IS NOT NULL AND TRIM(district) <> '' ORDER BY district")
    district_options = [row[0] for row in c.fetchall()]
    c.execute("SELECT DISTINCT city FROM complaints WHERE city IS NOT NULL AND TRIM(city) <> '' ORDER BY city")
    city_options = [row[0] for row in c.fetchall()]
    c.execute("SELECT DISTINCT pin_code FROM complaints WHERE pin_code IS NOT NULL AND TRIM(pin_code) <> '' ORDER BY pin_code")
    pin_options = [row[0] for row in c.fetchall()]
    query_args = request.args.to_dict(flat=False)
    query_args.pop('page', None)
    filter_query = urllib.parse.urlencode(query_args, doseq=True)

    conn.close()
    return render_template('police_dashboard.html',
                           complaints=complaints,
                           officer=officer,
                           is_admin_user=is_admin_user,
                           query=q,
                           page=page,
                           total_pages=total_pages,
                           total_count=total_count,
                           assignment_options=assignment_options,
                           unread_count=unread_count,
                           generated_reports=generated_reports,
                           district_options=district_options,
                           city_options=city_options,
                           pin_options=pin_options,
                           selected_districts=districts,
                           selected_cities=cities,
                           selected_pins=pin_codes,
                           selected_statuses=statuses,
                           from_date=from_date,
                           to_date=to_date,
                           filter_query=filter_query)


@app.route('/complaint/<int:complaint_id>/assign', methods=['POST'])
@police_required
def assign_complaint(complaint_id):
    if not validate_csrf():
        flash('Invalid request token. Please retry.', 'danger')
        return redirect(url_for('dashboard_police'))

    officer = get_current_officer_row()
    if not officer:
        session.clear()
        return redirect(url_for('login_police'))

    target_officer_id = request.form.get('officer_id', type=int)
    if not target_officer_id:
        flash('Please select an officer.', 'danger')
        return redirect(url_for('dashboard_police'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, district, city, pin_code, locality, report_id FROM complaints WHERE id = ?", (complaint_id,))
    complaint = c.fetchone()
    if not complaint:
        conn.close()
        flash('Complaint not found.', 'danger')
        return redirect(url_for('dashboard_police'))

    if not session.get('police_is_admin'):
        visible = (complaint[4] or '').lower() == (officer[7] or '').lower()
        if not visible:
            conn.close()
            flash('You are not allowed to assign this complaint.', 'danger')
            return redirect(url_for('dashboard_police'))

    c.execute("""SELECT id, full_name FROM police_officers
                 WHERE id = ? AND (LOWER(locality)=LOWER(?) OR LOWER(district)=LOWER(?) OR LOWER(city)=LOWER(?))""",
              (target_officer_id, complaint[4] or '', complaint[2] or '', complaint[3] or ''))
    target_officer = c.fetchone()
    if not target_officer and not session.get('police_is_admin'):
        conn.close()
        flash('Selected officer is outside complaint area.', 'danger')
        return redirect(url_for('dashboard_police'))
    if not target_officer:
        c.execute("SELECT id, full_name FROM police_officers WHERE id = ?", (target_officer_id,))
        target_officer = c.fetchone()
    if not target_officer:
        conn.close()
        flash('Officer not found.', 'danger')
        return redirect(url_for('dashboard_police'))

    now_iso = datetime.datetime.now().isoformat()
    c.execute("UPDATE complaints SET assigned_officer_id = ?, status = 'assigned' WHERE id = ?", (target_officer_id, complaint_id))
    c.execute("""INSERT INTO complaint_notifications (officer_id, complaint_id, message, is_read, created_at)
                 VALUES (?, ?, ?, 0, ?)""",
              (target_officer_id, complaint_id, f"You were assigned complaint {complaint[5]}.", now_iso))
    conn.commit()
    conn.close()
    flash('Complaint assigned successfully.', 'success')
    return redirect(url_for('dashboard_police'))


@app.route('/complaint/<int:complaint_id>/resolve', methods=['POST'])
@police_required
def resolve_complaint(complaint_id):
    if not validate_csrf():
        flash('Invalid request token. Please retry.', 'danger')
        return redirect(url_for('dashboard_police'))

    officer_id = session.get('officer_id')
    is_admin_user = bool(session.get('police_is_admin'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT assigned_officer_id, report_id FROM complaints WHERE id = ?", (complaint_id,))
    complaint = c.fetchone()
    if not complaint:
        conn.close()
        flash('Complaint not found.', 'danger')
        return redirect(url_for('dashboard_police'))
    if not is_admin_user and complaint[0] != officer_id:
        conn.close()
        flash('Only the assigned officer can resolve this complaint.', 'danger')
        return redirect(url_for('dashboard_police'))

    c.execute("UPDATE complaints SET status = 'resolved' WHERE id = ?", (complaint_id,))
    conn.commit()
    conn.close()
    flash('Complaint marked as resolved.', 'success')
    return redirect(url_for('dashboard_police'))


@app.route('/notifications/read_all', methods=['POST'])
@police_required
def read_all_notifications():
    if not validate_csrf():
        flash('Invalid request token. Please retry.', 'danger')
        return redirect(url_for('dashboard_police'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE complaint_notifications SET is_read = 1 WHERE officer_id = ?", (session.get('officer_id'),))
    conn.commit()
    conn.close()
    flash('Notifications marked as read.', 'success')
    return redirect(url_for('dashboard_police'))


@app.route('/api/complaint_count')
@police_required
def api_complaint_count():
    officer = get_current_officer_row()
    if not officer:
        return jsonify({'total': 0, 'new': 0})

    conn = get_db_connection()
    c = conn.cursor()
    if session.get('police_is_admin'):
        c.execute("SELECT COUNT(*) FROM complaints")
        total = c.fetchone()[0]
    else:
        scope_sql, scope_params = get_officer_scope_clause(officer)
        c.execute("SELECT COUNT(*) FROM complaints c WHERE " + scope_sql, scope_params)
        total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM complaint_notifications WHERE officer_id = ? AND is_read = 0", (officer[0],))
    new_count = c.fetchone()[0]
    conn.close()
    return jsonify({'total': total, 'new': new_count})


@app.route('/complaints/export')
@police_required
def export_complaints_csv():
    officer = get_current_officer_row()
    if not officer:
        return redirect(url_for('login_police'))
    conn = get_db_connection()
    c = conn.cursor()
    where_sql, params, *_ = build_complaint_filter(officer, bool(session.get('police_is_admin')), request.args)
    c.execute("""SELECT c.id, c.report_id, c.district, c.city, c.pin_code, c.locality, c.issue_category, c.complaint_text, c.created_at,
                        LOWER(COALESCE(c.status,'pending')) AS status, COALESCE(po.full_name, '')
                 FROM complaints c
                 LEFT JOIN police_officers po ON po.id = c.assigned_officer_id
              """ + where_sql + " ORDER BY c.id DESC", params)
    rows = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Report ID', 'District', 'City', 'PIN Code', 'Locality', 'Issue Category', 'Complaint Text', 'Created At', 'Status', 'Assigned Officer'])
    writer.writerows(rows)
    csv_data = output.getvalue()
    output.close()

    filename = f"complaints_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={filename}'})


@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""SELECT id, full_name, username, rank, district, city, pin_code, locality
                 FROM police_officers ORDER BY id DESC""")
    officers = c.fetchall()

    c.execute("""SELECT c.id, c.report_id, c.district, c.city, c.pin_code, c.locality, c.issue_category, c.complaint_text, c.created_at,
                        LOWER(COALESCE(c.status,'pending')) AS status, COALESCE(po.full_name, '')
                 FROM complaints c
                 LEFT JOIN police_officers po ON po.id = c.assigned_officer_id
                 ORDER BY c.id DESC LIMIT 100""")
    complaints = c.fetchall()

    c.execute("""SELECT district, COUNT(*) FROM complaints
                 GROUP BY district
                 ORDER BY COUNT(*) DESC""")
    complaints_by_district = c.fetchall()

    c.execute("""SELECT COALESCE(po.full_name, 'Unassigned') AS officer_name, COUNT(*) AS total
                 FROM complaints c
                 LEFT JOIN police_officers po ON po.id = c.assigned_officer_id
                 GROUP BY officer_name
                 ORDER BY total DESC""")
    complaints_by_officer = c.fetchall()
    conn.close()

    return render_template('admin_dashboard.html',
                           officers=officers,
                           complaints=complaints,
                           complaints_by_district=complaints_by_district,
                           complaints_by_officer=complaints_by_officer)


@app.route('/admin/officer/<int:officer_id>/edit', methods=['POST'])
@admin_required
def edit_officer(officer_id):
    if not validate_csrf():
        flash('Invalid request token. Please retry.', 'danger')
        return redirect(url_for('admin_dashboard'))

    full_name = sanitize_text(request.form.get('full_name', ''), 120)
    rank = sanitize_text(request.form.get('rank', ''), 80)
    district = sanitize_text(request.form.get('district', ''), 100)
    city = sanitize_text(request.form.get('city', ''), 100)
    pin_code = sanitize_text(request.form.get('pin_code', ''), 20)
    locality = sanitize_text(request.form.get('locality', ''), 100)
    if not all([full_name, rank, district, city, pin_code, locality]):
        flash('All officer fields are required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""UPDATE police_officers
                 SET full_name = ?, rank = ?, district = ?, city = ?, pin_code = ?, locality = ?
                 WHERE id = ?""", (full_name, rank, district, city, pin_code, locality, officer_id))
    conn.commit()
    conn.close()
    flash('Officer updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/officer/<int:officer_id>/delete', methods=['POST'])
@admin_required
def delete_officer_admin(officer_id):
    if not validate_csrf():
        flash('Invalid request token. Please retry.', 'danger')
        return redirect(url_for('admin_dashboard'))
    if officer_id == session.get('officer_id'):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE complaints SET assigned_officer_id = NULL, status = 'pending' WHERE assigned_officer_id = ?", (officer_id,))
    c.execute("DELETE FROM police_officers WHERE id = ?", (officer_id,))
    conn.commit()
    conn.close()
    flash('Officer deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/analytics_dashboard')
@admin_required
def analytics_dashboard():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""SELECT district, COUNT(*) FROM complaints
                 GROUP BY district ORDER BY COUNT(*) DESC""")
    district_stats = c.fetchall()

    c.execute("""SELECT LOWER(COALESCE(status,'pending')) AS status, COUNT(*)
                 FROM complaints
                 GROUP BY LOWER(COALESCE(status,'pending'))
                 ORDER BY COUNT(*) DESC""")
    status_stats = c.fetchall()

    c.execute("""SELECT date(created_at) AS day, COUNT(*)
                 FROM complaints
                 WHERE date(created_at) >= date('now', '-30 day')
                 GROUP BY day
                 ORDER BY day ASC""")
    trend_stats = c.fetchall()

    c.execute("""SELECT pin_code, COUNT(*) FROM complaints
                 WHERE pin_code IS NOT NULL AND TRIM(pin_code) <> ''
                 GROUP BY pin_code ORDER BY COUNT(*) DESC LIMIT 5""")
    top_pin_codes = c.fetchall()

    c.execute("""SELECT po.full_name,
                        COUNT(c.id) AS assigned_count,
                        SUM(CASE WHEN LOWER(COALESCE(c.status,'pending')) = 'resolved' THEN 1 ELSE 0 END) AS resolved_count
                 FROM police_officers po
                 LEFT JOIN complaints c ON c.assigned_officer_id = po.id
                 GROUP BY po.id, po.full_name
                 ORDER BY assigned_count DESC, resolved_count DESC""")
    officer_performance = c.fetchall()
    conn.close()

    return render_template('analytics_dashboard.html',
                           district_stats=district_stats,
                           status_stats=status_stats,
                           trend_stats=trend_stats,
                           top_pin_codes=top_pin_codes,
                           officer_performance=officer_performance)

@app.route('/update_report/<int:report_id>/<new_status>')
@police_required
def update_report(report_id, new_status):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE instant_reports SET status = ? WHERE id = ?", (new_status, report_id))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard_police'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('home'))

# ---------------- ADMIN PANEL ----------------

@app.route('/admin', methods=['GET'])
def admin():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username FROM police")
    police_users = c.fetchall()
    conn.close()
    return render_template('admin.html', police_users=police_users)

@app.route('/admin/add_police', methods=['POST'])
def add_police():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username and password required', 'danger')
        return redirect(url_for('admin'))
    
    try:
        hashed = generate_password_hash(password)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO police (username, password) VALUES (?,?)", (username, hashed))
        conn.commit()
        conn.close()
        flash(f'Police user {username} added successfully', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/delete_police/<int:user_id>', methods=['GET'])
def delete_police(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM police WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('Police user deleted', 'info')
    return redirect(url_for('admin'))

@app.route('/dashboard/officer')
def dashboard_officer():
    conn = get_db_connection()
    c = conn.cursor()
    # get reports for display
    c.execute("SELECT id, issue_type, description, location, anonymous, status, timestamp FROM instant_reports ORDER BY id DESC LIMIT 20")
    recent_reports = c.fetchall()
    # stats
    c.execute("SELECT COUNT(*) FROM instant_reports")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM instant_reports WHERE status='Pending'")
    pending = c.fetchone()[0]
    conn.close()
    return render_template('dashboard_officer.html', recent_reports=recent_reports, total=total, pending=pending)

# ---------------- REPORTS ----------------

@app.route('/reports')
def reports():
    # fetch all entries from database and show in a table
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT date, bus_no, location, issue FROM bus_reports ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return render_template('reports.html', reports=rows)


# ============ ADVANCED SAFETY FEATURES ============

# Route Safety Score
@app.route('/route_safety')
def route_safety():
    return render_template('route_safety.html')

# Virtual Guardian Mode
@app.route('/virtual_guardian')
def virtual_guardian():
    return render_template('virtual_guardian.html')

# Trusted Circle
@app.route('/trusted_circle')
def trusted_circle():
    return render_template('trusted_circle.html')

# Heatmap & Risk Intelligence
@app.route('/heatmap')
def heatmap():
    return render_template('heatmap.html')


# ---------------- RUN ----------------

if __name__ == '__main__':
    # listen on all network interfaces so the site is accessible from
    # other machines on the LAN (useful if you're testing from a phone
    # or another computer). keep debug=True for development.
    app.run(host='0.0.0.0', debug=True)
