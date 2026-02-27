from flask import Flask, render_template, request, session, redirect, url_for, flash
import sqlite3
import datetime
import urllib.parse
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from cryptography.fernet import Fernet
import os
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'suraksha_secret_key_2026')

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

# ================== DATABASE SETUP ==================

def init_db():
    conn = sqlite3.connect("database.db")
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
    
    # Police stations with location details
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
    
    # Insert sample police stations with location data
    c.execute("SELECT COUNT(*) FROM police_stations")
    if c.fetchone()[0] == 0:
        sample_stations = [
            ('Central Station', '123 Main Road, Fort', 'Mumbai Central', 'Mumbai', '400001', 18.9547, 72.8258, '9876543210'),
            ('Western Suburbs Station', '456 Western Express Hwy', 'Mumbai West', 'Mumbai', '400004', 19.1136, 72.8697, '9876543211'),
            ('Southern Station', '789 South Mumbai Avenue', 'Mumbai South', 'Mumbai', '400011', 18.9676, 72.8194, '9876543212'),
            ('Northern Station', '321 North Avenue', 'Mumbai North', 'Mumbai', '400024', 19.2183, 72.9781, '9876543213'),
            ('Eastern Station', '654 Eastern Region Road', 'Mumbai East', 'Mumbai', '400014', 19.0976, 72.8988, '9876543214'),
        ]
        for station in sample_stations:
            c.execute("""INSERT OR IGNORE INTO police_stations 
                        (station_name, address, district, city, pin_code, latitude, longitude, phone_number)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", station)
    
    conn.commit()
    conn.close()

init_db()

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

        conn = sqlite3.connect("database.db")
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
    conn = sqlite3.connect("database.db")
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
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    
    stations = []
    
    # Priority 1: Exact PIN code match
    if pin_code:
        c.execute("""SELECT id, station_name, address, district, city, pin_code, 
                            phone_number, latitude, longitude
                     FROM police_stations
                     WHERE pin_code = ? AND status = 'Active'
                     ORDER BY station_name""", (pin_code,))
        stations = c.fetchall()
    
    # Priority 2: Exact district match
    if not stations and district:
        c.execute("""SELECT id, station_name, address, district, city, pin_code, 
                            phone_number, latitude, longitude
                     FROM police_stations
                     WHERE district = ? AND status = 'Active'
                     ORDER BY station_name""", (district,))
        stations = c.fetchall()
    
    # Priority 3: City match
    if not stations and city:
        c.execute("""SELECT id, station_name, address, district, city, pin_code, 
                            phone_number, latitude, longitude
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
        c.execute("""SELECT id, full_name, contact_phone, official_email, badge_number
                     FROM police
                     WHERE district = ? AND role = 'officer' AND status = 'Active'
                     LIMIT 3""", (station_district,))
        
        officers = c.fetchall()
        stations_with_officers.append({
            'station': list(station),
            'officers': [list(o) for o in officers]
        })
    
    conn.close()
    return stations_with_officers

@app.route('/anonymous_complaint', methods=['GET', 'POST'])
def anonymous_complaint():
    """Secure anonymous complaint submission with encryption"""
    confirmation = None
    report_uuid = None
    
    if request.method == 'POST':
        # Collect complaint data
        district = request.form.get('district', '').strip()
        city = request.form.get('city', '').strip()
        pin_code = request.form.get('pin_code', '').strip()
        incident_date = request.form.get('incident_date', '')
        description = request.form.get('description', '').strip()
        issue_category = request.form.get('issue_category', 'General')
        selected_station_id = request.form.get('selected_station_id', None)
        
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
            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            
            # Store encrypted complaint (no PII stored in plain text)
            c.execute("""INSERT INTO anonymous_complaints 
                        (report_uuid, encrypted_data, district, city, pin_code, 
                         incident_date, submitted_at, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                     (report_uuid, encrypted_data, district, city, pin_code, 
                      incident_date, submitted_at, 'Pending'))
            
            complaint_id = c.lastrowid
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
    
    conn = sqlite3.connect("database.db")
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
    
    conn = sqlite3.connect("database.db")
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
        conn = sqlite3.connect("database.db")
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
        conn = sqlite3.connect("database.db")
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
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT id, full_name FROM police WHERE username = ? AND password = ?", (username, password))
        row = c.fetchone()
        if not row:
            c.execute("SELECT password FROM police WHERE username = ?", (username,))
            pwd_row = c.fetchone()
            if pwd_row and check_password_hash(pwd_row[0], password):
                session['police_logged_in'] = True
                session['police_user'] = username
                conn.close()
                return redirect(url_for('police_complaints'))
            else:
                error = 'Invalid username or password'
        else:
            session['police_logged_in'] = True
            session['police_user'] = username
            conn.close()
            return redirect(url_for('police_complaints'))
        conn.close()
    return render_template('police_login.html', error=error)

@app.route('/login/officer', methods=['GET','POST'])
def login_officer():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect("database.db")
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
    def wrapper(*args, **kwargs):
        if not session.get('police_logged_in'):
            return redirect(url_for('login_police'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper


def officer_required(f):
    def wrapper(*args, **kwargs):
        if not session.get('officer_logged_in'):
            return redirect(url_for('login_officer'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/dashboard/police')
@app.route('/police_dashboard')
@police_required
def dashboard_police():
    status_filter = request.args.get('status')
    q = request.args.get('q')
    date_filter = request.args.get('date')
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    query = "SELECT id, issue_type, description, location, anonymous, status, timestamp FROM instant_reports"
    params = []
    conditions = []
    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)
    if q:
        conditions.append("id = ?")
        params.append(q)
    if date_filter:
        conditions.append("date(timestamp) = ?")
        params.append(date_filter)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC"
    c.execute(query, params)
    reports = c.fetchall()
    # summary counts
    c.execute("SELECT status, COUNT(*) FROM instant_reports GROUP BY status")
    counts = dict(c.fetchall())
    conn.close()
    return render_template('dashboard_police.html', reports=reports, counts=counts, filter=status_filter, query=q, date_filter=date_filter)

@app.route('/update_report/<int:report_id>/<new_status>')
@police_required
def update_report(report_id, new_status):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("UPDATE instant_reports SET status = ? WHERE id = ?", (new_status, report_id))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard_police'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ---------------- ADMIN PANEL ----------------

@app.route('/admin', methods=['GET'])
def admin():
    conn = sqlite3.connect("database.db")
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
        conn = sqlite3.connect("database.db")
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
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("DELETE FROM police WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('Police user deleted', 'info')
    return redirect(url_for('admin'))

@app.route('/dashboard/officer')
def dashboard_officer():
    conn = sqlite3.connect("database.db")
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
    conn = sqlite3.connect("database.db")
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