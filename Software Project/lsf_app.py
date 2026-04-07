import os, jwt, bcrypt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from database import get_db, init_db

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app, origins='*')
SECRET = os.environ.get('JWT_SECRET', 'lsf-secret-2026')

# ── helpers ──────────────────────────────────────────────────────────────────

def make_token(uid, role):
    return jwt.encode(
        {'user_id': uid, 'role': role,
         'exp': datetime.now(timezone.utc) + timedelta(hours=24)},
        SECRET, algorithm='HS256'
    )

def r2d(row):  return dict(row) if row else None
def rs(rows):  return [dict(r) for r in rows]

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Token missing'}), 401
        try:
            data = jwt.decode(auth.split()[1], SECRET, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(data, *args, **kwargs)
    return wrapper

def role_required(*roles):
    def dec(f):
        @wraps(f)
        def wrapper(td, *a, **kw):
            if td.get('role') not in roles:
                return jsonify({'error': 'Forbidden'}), 403
            return f(td, *a, **kw)
        return token_required(wrapper)
    return dec

# ── static ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ── health ────────────────────────────────────────────────────────────────────

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()}), 200

# ── auth ──────────────────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    d = request.get_json(silent=True) or {}
    name, email, pw = d.get('name','').strip(), d.get('email','').strip().lower(), d.get('password','')
    role = d.get('role', 'customer')
    if not (name and email and pw):
        return jsonify({'error': 'name, email, password required'}), 400
    if role not in ('customer','provider','admin'):
        return jsonify({'error': 'Invalid role'}), 400
    db = get_db()
    if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
        db.close(); return jsonify({'error': 'Email already registered'}), 400
    ph = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    cur = db.execute('INSERT INTO users (name,email,password_hash,role,registration_number) VALUES (?,?,?,?,?)',
                     (name, email, ph, role, d.get('registration_number','')))
    uid = cur.lastrowid
    if role == 'provider':
        db.execute('INSERT INTO service_providers (user_id,category,location,bio,status) VALUES (?,?,?,?,?)',
                   (uid, d.get('category','General'), d.get('location','Unknown'), d.get('bio',''), 'pending'))
        db.execute('INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)',
                   (uid,'Registration received. Awaiting admin verification.','info'))
    db.commit(); db.close()
    return jsonify({'message': 'Registered', 'token': make_token(uid, role), 'role': role}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.get_json(silent=True) or {}
    email, pw = d.get('email','').strip().lower(), d.get('password','')
    if not (email and pw):
        return jsonify({'error': 'email and password required'}), 400
    db = get_db()
    u = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    db.close()
    if not u or not bcrypt.checkpw(pw.encode(), u['password_hash'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401
    return jsonify({'token': make_token(u['id'], u['role']),
                    'role': u['role'], 'name': u['name'], 'user_id': u['id']}), 200

@app.route('/api/auth/profile')
@token_required
def profile(td):
    db = get_db()
    u = r2d(db.execute('SELECT id,name,email,role,registration_number,created_at FROM users WHERE id=?',
                        (td['user_id'],)).fetchone())
    if not u: db.close(); return jsonify({'error': 'Not found'}), 404
    if td['role'] == 'provider':
        u['provider_profile'] = r2d(db.execute('SELECT * FROM service_providers WHERE user_id=?',
                                                (td['user_id'],)).fetchone())
    db.close()
    return jsonify(u), 200

# ── admin ─────────────────────────────────────────────────────────────────────

@app.route('/api/admin/users')
@role_required('admin')
def admin_users(td):
    db = get_db()
    data = rs(db.execute('SELECT id,name,email,role,registration_number,created_at FROM users ORDER BY created_at DESC').fetchall())
    db.close(); return jsonify(data), 200

@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
@role_required('admin')
def admin_del_user(td, uid):
    db = get_db()
    if not db.execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone():
        db.close(); return jsonify({'error':'Not found'}), 404
    db.execute('DELETE FROM users WHERE id=?',(uid,)); db.commit(); db.close()
    return jsonify({'message':'User deleted'}), 200

@app.route('/api/admin/providers/<int:pid>/verify', methods=['PUT'])
@role_required('admin')
def admin_verify(td, pid):
    d = request.get_json(silent=True) or {}
    status = d.get('status','verified')
    db = get_db()
    sp = db.execute('SELECT * FROM service_providers WHERE id=?',(pid,)).fetchone()
    if not sp: db.close(); return jsonify({'error':'Not found'}), 404
    db.execute('UPDATE service_providers SET status=? WHERE id=?',(status, pid))
    db.execute('INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)',
               (sp['user_id'], f'Your account status is now: {status}', 'success'))
    db.commit(); db.close()
    return jsonify({'message':f'Provider status set to {status}'}), 200

@app.route('/api/admin/bookings')
@role_required('admin')
def admin_bookings(td):
    db = get_db()
    data = rs(db.execute('''SELECT b.*,u.name customer_name,s.name service_name
        FROM bookings b JOIN users u ON b.customer_id=u.id
        JOIN services s ON b.service_id=s.id ORDER BY b.created_at DESC''').fetchall())
    db.close(); return jsonify(data), 200

@app.route('/api/admin/complaints')
@role_required('admin')
def admin_complaints(td):
    db = get_db()
    data = rs(db.execute('''SELECT c.*,u.name customer_name
        FROM complaints c JOIN users u ON c.customer_id=u.id
        ORDER BY c.created_at DESC''').fetchall())
    db.close(); return jsonify(data), 200

# ── provider ──────────────────────────────────────────────────────────────────

def get_sp(db, uid):
    return db.execute('SELECT id FROM service_providers WHERE user_id=?',(uid,)).fetchone()

@app.route('/api/providers/services', methods=['POST'])
@role_required('provider')
def prov_add_svc(td):
    d = request.get_json(silent=True) or {}
    db = get_db()
    sp = get_sp(db, td['user_id'])
    if not sp: db.close(); return jsonify({'error':'Provider profile not found'}), 404
    name=d.get('name','').strip(); cat=d.get('category','').strip(); price=d.get('price',0)
    if not (name and cat and price):
        db.close(); return jsonify({'error':'name, category, price required'}), 400
    cur = db.execute('INSERT INTO services (provider_id,name,category,description,price,availability) VALUES (?,?,?,?,?,?)',
                     (sp['id'], name, cat, d.get('description',''), float(price), d.get('availability','available')))
    db.commit()
    svc = r2d(db.execute('SELECT * FROM services WHERE id=?',(cur.lastrowid,)).fetchone())
    db.close(); return jsonify(svc), 201

@app.route('/api/providers/services/<int:sid>', methods=['PUT'])
@role_required('provider')
def prov_upd_svc(td, sid):
    d = request.get_json(silent=True) or {}
    db = get_db()
    sp = get_sp(db, td['user_id'])
    if not sp: db.close(); return jsonify({'error':'Provider not found'}), 404
    svc = db.execute('SELECT * FROM services WHERE id=? AND provider_id=?',(sid, sp['id'])).fetchone()
    if not svc: db.close(); return jsonify({'error':'Service not found'}), 404
    db.execute('UPDATE services SET name=?,category=?,description=?,price=?,availability=? WHERE id=?',
               (d.get('name',svc['name']), d.get('category',svc['category']),
                d.get('description',svc['description']), float(d.get('price',svc['price'])),
                d.get('availability',svc['availability']), sid))
    db.commit()
    updated = r2d(db.execute('SELECT * FROM services WHERE id=?',(sid,)).fetchone())
    db.close(); return jsonify(updated), 200

@app.route('/api/providers/bookings')
@role_required('provider')
def prov_bookings(td):
    db = get_db()
    sp = get_sp(db, td['user_id'])
    if not sp: db.close(); return jsonify([]), 200
    data = rs(db.execute('''SELECT b.*,u.name customer_name,s.name service_name
        FROM bookings b JOIN users u ON b.customer_id=u.id
        JOIN services s ON b.service_id=s.id
        WHERE b.provider_id=? ORDER BY b.created_at DESC''',(sp['id'],)).fetchall())
    db.close(); return jsonify(data), 200

@app.route('/api/providers/bookings/<int:bid>', methods=['PUT'])
@role_required('provider')
def prov_upd_booking(td, bid):
    d = request.get_json(silent=True) or {}
    status = d.get('status')
    if status not in ('confirmed','completed','cancelled'):
        return jsonify({'error':'Invalid status'}), 400
    db = get_db()
    sp = get_sp(db, td['user_id'])
    if not sp: db.close(); return jsonify({'error':'Provider not found'}), 404
    b = db.execute('SELECT * FROM bookings WHERE id=? AND provider_id=?',(bid, sp['id'])).fetchone()
    if not b: db.close(); return jsonify({'error':'Booking not found'}), 404
    db.execute('UPDATE bookings SET status=? WHERE id=?',(status, bid))
    db.execute('INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)',
               (b['customer_id'], f'Booking #{bid} status: {status}', 'booking'))
    db.commit(); db.close()
    return jsonify({'message':f'Updated to {status}'}), 200

@app.route('/api/providers/reviews')
@role_required('provider')
def prov_reviews(td):
    db = get_db()
    sp = get_sp(db, td['user_id'])
    if not sp: db.close(); return jsonify([]), 200
    data = rs(db.execute('''SELECT r.*,u.name customer_name,s.name service_name
        FROM reviews r JOIN users u ON r.customer_id=u.id
        JOIN services s ON r.service_id=s.id
        WHERE r.provider_id=? ORDER BY r.created_at DESC''',(sp['id'],)).fetchall())
    db.close(); return jsonify(data), 200

# ── public / customer ─────────────────────────────────────────────────────────

@app.route('/api/categories')
def categories():
    return jsonify(['Plumber','Electrician','Cleaner','Carpenter','Painter']), 200

@app.route('/api/providers')
def providers():
    db = get_db()
    data = rs(db.execute('''SELECT sp.*,u.name,u.email FROM service_providers sp
        JOIN users u ON sp.user_id=u.id WHERE sp.status='verified'
        ORDER BY sp.rating DESC''').fetchall())
    db.close(); return jsonify(data), 200

@app.route('/api/providers/<int:pid>')
def provider_detail(pid):
    db = get_db()
    p = r2d(db.execute('''SELECT sp.*,u.name,u.email FROM service_providers sp
        JOIN users u ON sp.user_id=u.id WHERE sp.id=?''',(pid,)).fetchone())
    if not p: db.close(); return jsonify({'error':'Not found'}), 404
    p['services'] = rs(db.execute("SELECT * FROM services WHERE provider_id=? AND availability='available'",(pid,)).fetchall())
    p['reviews']  = rs(db.execute('''SELECT r.*,u.name customer_name FROM reviews r
        JOIN users u ON r.customer_id=u.id WHERE r.provider_id=? ORDER BY r.created_at DESC''',(pid,)).fetchall())
    db.close(); return jsonify(p), 200

@app.route('/api/services')
def services():
    cat = request.args.get('category','').strip()
    loc = request.args.get('location','').strip()
    db = get_db()
    q = '''SELECT s.*,sp.location,sp.rating,u.name provider_name FROM services s
        JOIN service_providers sp ON s.provider_id=sp.id
        JOIN users u ON sp.user_id=u.id
        WHERE s.availability='available' AND sp.status='verified' '''
    params = []
    if cat:  q += ' AND s.category=?';         params.append(cat)
    if loc:  q += ' AND sp.location LIKE ?';   params.append(f'%{loc}%')
    q += ' ORDER BY sp.rating DESC'
    data = rs(db.execute(q, params).fetchall())
    db.close(); return jsonify(data), 200

@app.route('/api/services/<int:sid>')
def service_detail(sid):
    db = get_db()
    s = r2d(db.execute('''SELECT s.*,sp.location,sp.rating,sp.bio,u.name provider_name
        FROM services s JOIN service_providers sp ON s.provider_id=sp.id
        JOIN users u ON sp.user_id=u.id WHERE s.id=?''',(sid,)).fetchone())
    db.close()
    if not s: return jsonify({'error':'Not found'}), 404
    return jsonify(s), 200

@app.route('/api/bookings', methods=['POST'])
@token_required
def create_booking(td):
    if td['role'] not in ('customer','admin'):
        return jsonify({'error':'Only customers can book'}), 403
    d = request.get_json(silent=True) or {}
    sid = d.get('service_id'); date = d.get('date',''); ts = d.get('timeslot','')
    if not (sid and date and ts):
        return jsonify({'error':'service_id, date, timeslot required'}), 400
    db = get_db()
    svc = db.execute('SELECT * FROM services WHERE id=?',(sid,)).fetchone()
    if not svc: db.close(); return jsonify({'error':'Service not found'}), 404
    cur = db.execute('INSERT INTO bookings (customer_id,service_id,provider_id,date,timeslot,status,total_cost) VALUES (?,?,?,?,?,?,?)',
                     (td['user_id'], sid, svc['provider_id'], date, ts, 'pending', svc['price']))
    bid = cur.lastrowid
    sp = db.execute('SELECT user_id FROM service_providers WHERE id=?',(svc['provider_id'],)).fetchone()
    if sp:
        db.execute('INSERT INTO notifications (user_id,message,type) VALUES (?,?,?)',
                   (sp['user_id'], f'New booking #{bid} for {svc["name"]}', 'booking'))
    db.commit()
    bk = r2d(db.execute('SELECT * FROM bookings WHERE id=?',(bid,)).fetchone())
    db.close(); return jsonify(bk), 201

@app.route('/api/bookings')
@token_required
def get_bookings(td):
    db = get_db()
    if td['role'] == 'customer':
        data = rs(db.execute('''SELECT b.*,s.name service_name,u.name provider_name
            FROM bookings b JOIN services s ON b.service_id=s.id
            JOIN service_providers sp ON b.provider_id=sp.id
            JOIN users u ON sp.user_id=u.id
            WHERE b.customer_id=? ORDER BY b.created_at DESC''',(td['user_id'],)).fetchall())
    else:
        data = rs(db.execute('''SELECT b.*,s.name service_name,u.name customer_name
            FROM bookings b JOIN services s ON b.service_id=s.id
            JOIN users u ON b.customer_id=u.id ORDER BY b.created_at DESC''').fetchall())
    db.close(); return jsonify(data), 200

@app.route('/api/bookings/<int:bid>/cancel', methods=['PUT'])
@token_required
def cancel_booking(td, bid):
    db = get_db()
    b = db.execute('SELECT * FROM bookings WHERE id=?',(bid,)).fetchone()
    if not b: db.close(); return jsonify({'error':'Not found'}), 404
    if td['role'] == 'customer' and b['customer_id'] != td['user_id']:
        db.close(); return jsonify({'error':'Forbidden'}), 403
    if b['status'] in ('completed','cancelled'):
        db.close(); return jsonify({'error':f'Cannot cancel a {b["status"]} booking'}), 400
    db.execute('UPDATE bookings SET status=? WHERE id=?',('cancelled', bid))
    db.commit(); db.close()
    return jsonify({'message':'Booking cancelled'}), 200

@app.route('/api/reviews', methods=['POST'])
@token_required
def post_review(td):
    if td['role'] != 'customer':
        return jsonify({'error':'Only customers can review'}), 403
    d = request.get_json(silent=True) or {}
    pid=d.get('provider_id'); sid=d.get('service_id'); rating=d.get('rating')
    if not (pid and sid and rating):
        return jsonify({'error':'provider_id, service_id, rating required'}), 400
    if not (1 <= int(rating) <= 5):
        return jsonify({'error':'Rating must be 1-5'}), 400
    db = get_db()
    cur = db.execute('INSERT INTO reviews (customer_id,provider_id,service_id,rating,comment) VALUES (?,?,?,?,?)',
                     (td['user_id'], pid, sid, int(rating), d.get('comment','')))
    db.execute('UPDATE service_providers SET rating=(SELECT ROUND(AVG(rating),1) FROM reviews WHERE provider_id=?) WHERE id=?',
               (pid, pid))
    db.commit()
    rv = r2d(db.execute('SELECT * FROM reviews WHERE id=?',(cur.lastrowid,)).fetchone())
    db.close(); return jsonify(rv), 201

@app.route('/api/complaints', methods=['POST'])
@token_required
def post_complaint(td):
    d = request.get_json(silent=True) or {}
    desc = d.get('description','').strip()
    if not desc: return jsonify({'error':'description required'}), 400
    db = get_db()
    cur = db.execute('INSERT INTO complaints (customer_id,description) VALUES (?,?)',(td['user_id'], desc))
    db.commit()
    c = r2d(db.execute('SELECT * FROM complaints WHERE id=?',(cur.lastrowid,)).fetchone())
    db.close(); return jsonify(c), 201

@app.route('/api/notifications')
@token_required
def notifications(td):
    db = get_db()
    data = rs(db.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC',(td['user_id'],)).fetchall())
    db.execute('UPDATE notifications SET is_read=1 WHERE user_id=?',(td['user_id'],))
    db.commit(); db.close()
    return jsonify(data), 200

# ── entry ─────────────────────────────────────────────────────────────────────

init_db()
if __name__ == '__main__':
    # init_db()
    # app.run(debug=True, threaded=True, port=5001)
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
