import sqlite3
import bcrypt
from datetime import datetime, timedelta
from models import CREATE_TABLES_SQL

DATABASE = 'local_services.db'


def get_db():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    for sql in CREATE_TABLES_SQL:
        conn.execute(sql)
    conn.commit()
    seed_data(conn)
    conn.close()


def hpw(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def seed_data(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        return

    # Admin
    cur.execute(
        "INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
        ('Admin User', 'admin@lsf.com', hpw('admin123'), 'admin')
    )
    admin_id = cur.lastrowid

    # Service Providers
    providers_meta = [
        ('Plumber Pro',     'provider1@lsf.com', 'REG1001', 'Plumber',    'Downtown', 'Expert plumber with 10 yrs experience.'),
        ('Electrician Pro', 'provider2@lsf.com', 'REG1002', 'Electrician','Midtown',  'Certified residential & commercial electrician.'),
        ('Cleaner Pro',     'provider3@lsf.com', 'REG1003', 'Cleaner',    'Uptown',   'Professional home and office cleaner.'),
        ('Carpenter Pro',   'provider4@lsf.com', 'REG1004', 'Carpenter',  'Suburbs',  'Custom furniture and woodwork specialist.'),
        ('Painter Pro',     'provider5@lsf.com', 'REG1005', 'Painter',    'East Side','Creative painter for interiors & exteriors.'),
    ]
    sp_ids = []
    puser_ids = []
    for i, (name, email, reg, cat, loc, bio) in enumerate(providers_meta, 1):
        cur.execute(
            "INSERT INTO users (name,email,password_hash,role,registration_number) VALUES (?,?,?,?,?)",
            (name, email, hpw(f'provider{i}123'), 'provider', reg)
        )
        uid = cur.lastrowid
        puser_ids.append(uid)
        cur.execute(
            "INSERT INTO service_providers (user_id,category,location,rating,status,bio) VALUES (?,?,?,?,?,?)",
            (uid, cat, loc, round(3.5 + i * 0.1, 1), 'verified', bio)
        )
        sp_ids.append(cur.lastrowid)

    # Customers
    cust_ids = []
    for i in range(1, 11):
        cur.execute(
            "INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
            (f'Customer {i}', f'customer{i}@lsf.com', hpw(f'customer{i}123'), 'customer')
        )
        cust_ids.append(cur.lastrowid)

    # Services (20 listings, 4 per provider)
    services_raw = [
        (sp_ids[0], 'Pipe Leak Repair',        'Plumber',     'Fix any pipe leaks quickly.',               80.0),
        (sp_ids[0], 'Drain Unclogging',         'Plumber',     'Unclog sinks, toilets, and drains.',        60.0),
        (sp_ids[0], 'Water Heater Install',     'Plumber',     'Install and configure water heaters.',     150.0),
        (sp_ids[0], 'Bathroom Fixture Fitting', 'Plumber',     'Install faucets, showers, and taps.',      120.0),
        (sp_ids[1], 'Wiring Installation',      'Electrician', 'Full home wiring setup.',                  200.0),
        (sp_ids[1], 'Circuit Breaker Repair',   'Electrician', 'Fix tripping breakers safely.',            100.0),
        (sp_ids[1], 'Lighting Setup',           'Electrician', 'Install smart & decorative lighting.',      90.0),
        (sp_ids[1], 'Appliance Installation',   'Electrician', 'Install AC, washer, and appliances.',      130.0),
        (sp_ids[2], 'Deep Home Cleaning',       'Cleaner',     'Thorough deep clean of entire home.',       75.0),
        (sp_ids[2], 'Office Cleaning',          'Cleaner',     'Maintain spotless office environments.',    65.0),
        (sp_ids[2], 'Carpet Cleaning',          'Cleaner',     'Steam clean carpets and rugs.',             85.0),
        (sp_ids[2], 'Post-Renovation Cleanup',  'Cleaner',     'Clear debris after construction work.',    110.0),
        (sp_ids[3], 'Custom Furniture Build',   'Carpenter',   'Build bespoke furniture to your design.',  300.0),
        (sp_ids[3], 'Cabinet Installation',     'Carpenter',   'Install kitchen and bathroom cabinets.',   180.0),
        (sp_ids[3], 'Door & Window Fitting',    'Carpenter',   'Fit or repair doors and windows.',         140.0),
        (sp_ids[3], 'Flooring Installation',    'Carpenter',   'Lay hardwood or laminate flooring.',       250.0),
        (sp_ids[4], 'Interior Painting',        'Painter',     'Paint walls, ceilings, and trims.',        200.0),
        (sp_ids[4], 'Exterior Painting',        'Painter',     'Weather-resistant exterior coats.',        350.0),
        (sp_ids[4], 'Wallpaper Hanging',        'Painter',     'Apply and align decorative wallpapers.',   160.0),
        (sp_ids[4], 'Texture Finish Painting',  'Painter',     'Apply sponge or stucco texture effects.',  220.0),
    ]
    svc_ids = []
    for sp_id, name, cat, desc, price in services_raw:
        cur.execute(
            "INSERT INTO services (provider_id,name,category,description,price,availability) VALUES (?,?,?,?,?,?)",
            (sp_id, name, cat, desc, price, 'available')
        )
        svc_ids.append(cur.lastrowid)

    # Bookings (15, mixed statuses)
    statuses  = ['pending', 'confirmed', 'completed', 'cancelled']
    timeslots = ['09:00 AM', '11:00 AM', '01:00 PM', '03:00 PM', '05:00 PM']
    for i in range(15):
        cid  = cust_ids[i % len(cust_ids)]
        sid  = svc_ids[i % len(svc_ids)]
        pid  = services_raw[i % len(services_raw)][0]   # sp_id from services_raw
        date = (datetime(2026, 4, 10) + timedelta(days=i)).strftime('%Y-%m-%d')
        cur.execute(
            "INSERT INTO bookings (customer_id,service_id,provider_id,date,timeslot,status,total_cost) VALUES (?,?,?,?,?,?,?)",
            (cid, sid, pid, date, timeslots[i % 5], statuses[i % 4], services_raw[i % len(services_raw)][4])
        )

    # Reviews (10, ratings 3-5)
    comments = [
        'Great service, very professional!', 'Arrived on time and did excellent work.',
        'Satisfied with the quality.', 'Good experience overall.',
        'Highly recommend this provider!', 'Very thorough and efficient.',
        'Friendly and skilled professional.', 'Exceeded my expectations!',
        'Clean workmanship, no complaints.', 'Will definitely book again.',
    ]
    for i in range(10):
        cid = cust_ids[i % len(cust_ids)]
        pid = sp_ids[i % len(sp_ids)]
        sid = svc_ids[i % len(svc_ids)]
        cur.execute(
            "INSERT INTO reviews (customer_id,provider_id,service_id,rating,comment) VALUES (?,?,?,?,?)",
            (cid, pid, sid, (i % 3) + 3, comments[i])
        )
        cur.execute(
            "UPDATE service_providers SET rating=(SELECT ROUND(AVG(rating),1) FROM reviews WHERE provider_id=?) WHERE id=?",
            (pid, pid)
        )

    # Notifications
    cur.execute(
        "INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)",
        (admin_id, 'Welcome to Local Services Finder as Admin!', 'info')
    )
    for uid in puser_ids:
        cur.execute(
            "INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)",
            (uid, 'Your provider account has been verified!', 'success')
        )
    for uid in cust_ids[:3]:
        cur.execute(
            "INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)",
            (uid, 'Welcome to Local Services Finder!', 'info')
        )
    conn.commit()
    print("Database seeded successfully.")
