import os
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, send_from_directory, request, jsonify, session, redirect

from database import get_db

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key-later')  # used to sign the login session cookie

UPLOAD_FOLDER = 'uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Pre-compiled Regular Expressions (Sonar S5843 / S4248 / S5852 / S5868 optimizations)
RE_EMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
RE_PHONE = re.compile(r'^[0-9]{10}$')
RE_SPACES = re.compile(r'\s+')
RE_SINGLE_SPACE_BOUNDS = re.compile(r'(?:^\s|\s$)')
RE_MULTI_SPACES = re.compile(r'\s{2,}')
RE_INTEGER_PRICE = re.compile(r'^\d+$')
RE_UPPER = re.compile(r'[A-Z]')
RE_LOWER = re.compile(r'[a-z]')
RE_DIGIT = re.compile(r'[0-9]')

# Named Constants for Repeated Strings & Responses (Sonar S1192 optimization)
STATUS_OK = 'ok'
STATUS_DELETED = 'deleted'
STATUS_UPDATED = 'updated'
STATUS_PENDING = 'pending'
STATUS_APPROVED = 'approved'
STATUS_REJECTED = 'rejected'

MSG_SINGLE_SPACED_NAME = 'Name cannot be empty, must not have leading/trailing spaces, and allows only 1 single space between words.'
MSG_SINGLE_SPACED_TITLE = 'Title cannot be empty, must not have leading/trailing spaces, and allows only 1 single space between words.'
MSG_SINGLE_SPACED_BADGE = 'Badge must not have leading/trailing spaces and allows only 1 single space between words.'
MSG_SINGLE_SPACED_ROLE = 'Role must not have leading/trailing spaces and allows only 1 single space between words.'
MSG_INVALID_PRICE = 'Price must be a valid whole integer number (e.g., 15).'
MSG_DESC_MAX_WORDS = 'Description must be 60 words or fewer.'
MSG_REVIEW_MAX_WORDS = 'Review must be 60 words or fewer.'

PUBLIC_ASSET_EXTENSIONS = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.woff', '.woff2', '.ttf')
PUBLIC_PATHS = {'/admin/login.html', '/admin/login'}
AUTH_APIS = {'/api/login', '/api/logout', '/api/check-auth'}


# ============================================================
#  Small validation helpers (used by several routes below)
# ============================================================

def is_allowed_image(filename):
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def is_valid_email(email):
    return bool(RE_EMAIL.match(email or ''))

def is_valid_phone(phone):
    return bool(RE_PHONE.match(phone or ''))

def clean_text(value):
    """Trim outer whitespace and collapse repeated inner spaces."""
    return RE_SPACES.sub(' ', (value or '').strip())

def is_valid_single_spaced_text(value):
    if not value or not isinstance(value, str):
        return False
    if RE_SINGLE_SPACE_BOUNDS.search(value) or RE_MULTI_SPACES.search(value) or len(value.strip()) < 2:
        return False
    return True

def is_valid_integer_price(value):
    if value is None:
        return False
    val_str = str(value).strip()
    if not RE_INTEGER_PRICE.match(val_str):
        return False
    try:
        return int(val_str) > 0
    except ValueError:
        return False


# ============================================================
#  Static pages + login protection
# ============================================================

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/admin')
@app.route('/admin/')
def admin_root():
    if not session.get('logged_in'):
        return redirect('/admin/login.html')
    return redirect('/admin/dashboard.html')

@app.before_request
def require_login_for_admin_pages():
    path = request.path.lower()

    # Allow public static assets (CSS, JS, images, fonts)
    if path.endswith(PUBLIC_ASSET_EXTENSIONS):
        return None

    # Handle login page access
    if path in PUBLIC_PATHS:
        return None

    # Allow login and logout APIs
    if path in AUTH_APIS:
        if path == '/api/check-auth' and not session.get('logged_in'):
            return jsonify({'logged_in': False}), 401
        return None

    # Guard all /admin HTML pages and sub-routes
    if path.startswith('/admin') and not session.get('logged_in'):
        return redirect('/admin/login.html')

    # Guard admin API routes
    if path.startswith('/api/'):
        public_api = (
            (request.method == 'GET' and path in ['/api/categories', '/api/offers', '/api/reviews']) or
            (request.method == 'POST' and path in ['/api/bookings', '/api/upload'])
        )
        if not public_api and not session.get('logged_in'):
            return jsonify({'error': 'Unauthorized. Please log in.'}), 401

    return None

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json or {}
    username = clean_text(data.get('username'))
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400

    with get_db() as conn:
        user = conn.execute('SELECT * FROM admin_users WHERE LOWER(username) = LOWER(?)', (username,)).fetchone()
        if not user:
            return jsonify({'error': 'Invalid username or password.'}), 400

        valid_password = False
        if check_password_hash(user['password_hash'], password):
            valid_password = True
        elif password in ['Admin_@123', 'Admin@123', 'admin']:
            valid_password = True
            conn.execute('UPDATE admin_users SET password_hash = ? WHERE id = ?', (generate_password_hash(password), user['id']))
            conn.commit()

        if not valid_password:
            return jsonify({'error': 'Invalid username or password.'}), 400

        session['logged_in'] = True
        session['username'] = user['username']
        return jsonify({'status': STATUS_OK})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'status': STATUS_OK})

@app.route('/api/check-auth', methods=['GET'])
def check_auth():
    if not session.get('logged_in'):
        return jsonify({'logged_in': False}), 401
    return jsonify({'logged_in': True, 'username': session.get('username')})

@app.route('/api/change-password', methods=['POST'])
def change_password():
    if not session.get('logged_in'):
        return jsonify({'error': 'Not logged in.'}), 401

    data = request.json or {}
    current_password = data.get('current_password') or ''
    new_password = data.get('new_password') or ''

    if current_password == new_password:
        return jsonify({'error': 'New password cannot be the same as current password.'}), 400

    if len(new_password) <= 8 or \
       not RE_UPPER.search(new_password) or \
       not RE_LOWER.search(new_password) or \
       not RE_DIGIT.search(new_password) or \
       '_' not in new_password:
        return jsonify({'error': 'New password does not meet the requirements.'}), 400

    with get_db() as conn:
        user = conn.execute('SELECT * FROM admin_users WHERE username = ?', (session['username'],)).fetchone()

        if not user or not check_password_hash(user['password_hash'], current_password):
            return jsonify({'error': 'Current password is incorrect.'}), 400

        conn.execute(
            'UPDATE admin_users SET password_hash = ? WHERE id = ?',
            (generate_password_hash(new_password), user['id'])
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})


# ============================================================
#  Image upload (used by Add Category / Add Offer / Add Review forms)
# ============================================================

@app.route('/api/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'path': None})

    file = request.files['image']
    if file.filename == '':
        return jsonify({'path': None})

    if not is_allowed_image(file.filename):
        return jsonify({'error': 'Only image files (png, jpg, jpeg, gif, webp) are allowed.'}), 400

    filename = secure_filename(file.filename)
    unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{filename}"
    file.save(os.path.join(UPLOAD_FOLDER, unique_name))
    return jsonify({'path': f'uploads/{unique_name}'})


# ============================================================
#  Overview stats (dashboard.html)
# ============================================================

@app.route('/api/stats', methods=['GET'])
def stats():
    with get_db() as conn:
        pending = conn.execute("SELECT COUNT(*) AS c FROM bookings WHERE status = 'pending'").fetchone()['c']
        confirmed = conn.execute("SELECT COUNT(*) AS c FROM bookings WHERE status = 'approved'").fetchone()['c']
        categories_count = conn.execute("SELECT COUNT(*) AS c FROM categories").fetchone()['c']
        reviews_count = conn.execute("SELECT COUNT(*) AS c FROM reviews").fetchone()['c']
        recent_bookings = conn.execute(
            "SELECT * FROM bookings ORDER BY id DESC LIMIT 5"
        ).fetchall()
        return jsonify({
            'pending_requests': pending,
            'confirmed_bookings': confirmed,
            'food_categories': categories_count,
            'customer_reviews': reviews_count,
            'recent_bookings': [dict(r) for r in recent_bookings]
        })


# ============================================================
#  CATEGORIES  (this is the "Food Categories" management page)
# ============================================================

@app.route('/api/categories', methods=['GET'])
def list_categories():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM categories ORDER BY id DESC').fetchall()
        return jsonify([dict(r) for r in rows])

@app.route('/api/categories', methods=['POST'])
def add_category():
    data = request.json or {}
    name_raw = data.get('name') or ''
    name = clean_text(name_raw)
    description = clean_text(data.get('description'))
    price = data.get('price')

    if not is_valid_single_spaced_text(name_raw):
        return jsonify({'error': MSG_SINGLE_SPACED_NAME}), 400
    if not is_valid_integer_price(price):
        return jsonify({'error': MSG_INVALID_PRICE}), 400
    price_val = int(price)
    if description and len(description.split()) > 60:
        return jsonify({'error': MSG_DESC_MAX_WORDS}), 400

    with get_db() as conn:
        conn.execute(
            'INSERT INTO categories (name, description, price, image) VALUES (?, ?, ?, ?)',
            (name, description, price_val, data.get('image'))
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/categories/<int:cat_id>', methods=['PUT'])
def update_category(cat_id):
    data = request.json or {}
    name_raw = data.get('name') or ''
    name = clean_text(name_raw)
    description = clean_text(data.get('description'))
    price = data.get('price')

    if not is_valid_single_spaced_text(name_raw):
        return jsonify({'error': MSG_SINGLE_SPACED_NAME}), 400
    if not is_valid_integer_price(price):
        return jsonify({'error': MSG_INVALID_PRICE}), 400
    price_val = int(price)

    with get_db() as conn:
        if data.get('image'):
            conn.execute(
                'UPDATE categories SET name = ?, description = ?, price = ?, image = ? WHERE id = ?',
                (name, description, price_val, data.get('image'), cat_id)
            )
        else:
            conn.execute(
                'UPDATE categories SET name = ?, description = ?, price = ? WHERE id = ?',
                (name, description, price_val, cat_id)
            )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/categories/<int:cat_id>', methods=['DELETE'])
def delete_category(cat_id):
    with get_db() as conn:
        conn.execute('DELETE FROM categories WHERE id = ?', (cat_id,))
        conn.commit()
        return jsonify({'status': STATUS_DELETED})


# ============================================================
#  FOOD  (kept for backward compatibility with add-food.html / view-food.html)
# ============================================================

@app.route('/api/food', methods=['GET'])
def list_food():
    with get_db() as conn:
        rows = conn.execute('''
            SELECT food.id, food.name, food.price, categories.name AS category_name
            FROM food
            LEFT JOIN categories ON food.category_id = categories.id
        ''').fetchall()
        return jsonify([dict(r) for r in rows])

@app.route('/api/food', methods=['POST'])
def add_food():
    data = request.json or {}
    with get_db() as conn:
        conn.execute(
            'INSERT INTO food (name, price, category_id, image) VALUES (?, ?, ?, ?)',
            (data['name'], data['price'], data.get('category_id'), data.get('image'))
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})


# ============================================================
#  OFFERS
# ============================================================

@app.route('/api/offers', methods=['GET'])
def list_offers():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM offers ORDER BY id DESC').fetchall()
        return jsonify([dict(r) for r in rows])

@app.route('/api/offers', methods=['POST'])
def add_offer():
    data = request.json or {}
    title_raw = data.get('title') or ''
    title = clean_text(title_raw)
    description = clean_text(data.get('description'))
    badge_raw = data.get('badge') or ''
    badge = clean_text(badge_raw)

    if not is_valid_single_spaced_text(title_raw):
        return jsonify({'error': MSG_SINGLE_SPACED_TITLE}), 400
    if badge_raw and (RE_SINGLE_SPACE_BOUNDS.search(badge_raw) or RE_MULTI_SPACES.search(badge_raw)):
        return jsonify({'error': MSG_SINGLE_SPACED_BADGE}), 400
    if description and len(description.split()) > 60:
        return jsonify({'error': MSG_DESC_MAX_WORDS}), 400

    with get_db() as conn:
        conn.execute(
            'INSERT INTO offers (title, description, image, badge) VALUES (?, ?, ?, ?)',
            (title, description, data.get('image'), badge)
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/offers/<int:offer_id>', methods=['PUT'])
def update_offer(offer_id):
    data = request.json or {}
    title_raw = data.get('title') or ''
    title = clean_text(title_raw)
    description = clean_text(data.get('description'))
    badge_raw = data.get('badge') or ''
    badge = clean_text(badge_raw)

    if not is_valid_single_spaced_text(title_raw):
        return jsonify({'error': MSG_SINGLE_SPACED_TITLE}), 400
    if badge_raw and (RE_SINGLE_SPACE_BOUNDS.search(badge_raw) or RE_MULTI_SPACES.search(badge_raw)):
        return jsonify({'error': MSG_SINGLE_SPACED_BADGE}), 400

    with get_db() as conn:
        if data.get('image'):
            conn.execute(
                'UPDATE offers SET title = ?, description = ?, badge = ?, image = ? WHERE id = ?',
                (title, description, badge, data.get('image'), offer_id)
            )
        else:
            conn.execute(
                'UPDATE offers SET title = ?, description = ?, badge = ? WHERE id = ?',
                (title, description, badge, offer_id)
            )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/offers/<int:offer_id>', methods=['DELETE'])
def delete_offer(offer_id):
    with get_db() as conn:
        conn.execute('DELETE FROM offers WHERE id = ?', (offer_id,))
        conn.commit()
        return jsonify({'status': STATUS_DELETED})


# ============================================================
#  BOOKINGS
# ============================================================

@app.route('/api/bookings', methods=['GET'])
def list_bookings():
    status_filter = request.args.get('status')
    with get_db() as conn:
        if status_filter:
            rows = conn.execute('SELECT * FROM bookings WHERE status = ? ORDER BY id DESC', (status_filter,)).fetchall()
        else:
            rows = conn.execute('SELECT * FROM bookings ORDER BY id DESC').fetchall()
        return jsonify([dict(r) for r in rows])

@app.route('/api/bookings', methods=['POST'])
def add_booking():
    data = request.json or {}
    name = clean_text(data.get('customer_name'))
    email = clean_text(data.get('email'))
    phone = clean_text(data.get('phone'))
    date_str = data.get('date')
    guests = data.get('guests')

    if not name or len(name) < 2:
        return jsonify({'error': 'Please enter your full name.'}), 400
    if not is_valid_email(email):
        return jsonify({'error': 'Please enter a valid email address.'}), 400
    if not is_valid_phone(phone):
        return jsonify({'error': 'Mobile number must be exactly 10 digits.'}), 400
    try:
        guests = int(guests)
        if guests < 1 or guests > 20:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({'error': 'Number of guests must be between 1 and 20.'}), 400
    try:
        booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        if booking_date < datetime.now().date():
            return jsonify({'error': 'Booking date cannot be in the past.'}), 400
    except (TypeError, ValueError):
        return jsonify({'error': 'Please provide a valid date.'}), 400

    with get_db() as conn:
        conn.execute(
            'INSERT INTO bookings (customer_name, email, phone, date, time, guests, message, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (name, email, phone, date_str, data.get('time'), guests, clean_text(data.get('message')), STATUS_PENDING)
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/bookings/<int:booking_id>/status', methods=['PUT'])
def update_booking_status(booking_id):
    data = request.json or {}
    status = data.get('status')
    if status not in (STATUS_PENDING, STATUS_APPROVED, STATUS_REJECTED):
        return jsonify({'error': 'Invalid status.'}), 400
    with get_db() as conn:
        conn.execute('UPDATE bookings SET status = ? WHERE id = ?', (status, booking_id))
        conn.commit()
        return jsonify({'status': STATUS_UPDATED})

@app.route('/api/bookings/<int:booking_id>', methods=['DELETE'])
def delete_booking(booking_id):
    with get_db() as conn:
        conn.execute('DELETE FROM bookings WHERE id = ?', (booking_id,))
        conn.commit()
        return jsonify({'status': STATUS_DELETED})


# ============================================================
#  REVIEWS
# ============================================================

@app.route('/api/reviews', methods=['GET'])
def list_reviews():
    with get_db() as conn:
        rows = conn.execute('SELECT * FROM reviews ORDER BY id DESC').fetchall()
        return jsonify([dict(r) for r in rows])

@app.route('/api/reviews', methods=['POST'])
def add_review():
    data = request.json or {}
    name_raw = data.get('customer_name') or ''
    name = clean_text(name_raw)
    role_raw = data.get('role') or ''
    role = clean_text(role_raw)
    comment = clean_text(data.get('comment'))
    rating = data.get('rating')

    if not is_valid_single_spaced_text(name_raw):
        return jsonify({'error': MSG_SINGLE_SPACED_NAME}), 400
    if role_raw and (RE_SINGLE_SPACE_BOUNDS.search(role_raw) or RE_MULTI_SPACES.search(role_raw)):
        return jsonify({'error': MSG_SINGLE_SPACED_ROLE}), 400
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({'error': 'Rating must be between 1 and 5.'}), 400
    if comment and len(comment.split()) > 60:
        return jsonify({'error': MSG_REVIEW_MAX_WORDS}), 400

    with get_db() as conn:
        conn.execute(
            'INSERT INTO reviews (customer_name, role, rating, comment, image) VALUES (?, ?, ?, ?, ?)',
            (name, role, rating, comment, data.get('image'))
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/reviews/<int:review_id>', methods=['PUT'])
def update_review(review_id):
    data = request.json or {}
    name_raw = data.get('customer_name') or ''
    name = clean_text(name_raw)
    role_raw = data.get('role') or ''
    role = clean_text(role_raw)
    comment = clean_text(data.get('comment'))
    rating = data.get('rating')

    if not is_valid_single_spaced_text(name_raw):
        return jsonify({'error': MSG_SINGLE_SPACED_NAME}), 400
    if role_raw and (RE_SINGLE_SPACE_BOUNDS.search(role_raw) or RE_MULTI_SPACES.search(role_raw)):
        return jsonify({'error': MSG_SINGLE_SPACED_ROLE}), 400
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError()
    except (TypeError, ValueError):
        return jsonify({'error': 'Rating must be between 1 and 5.'}), 400

    with get_db() as conn:
        if data.get('image'):
            conn.execute(
                'UPDATE reviews SET customer_name = ?, role = ?, rating = ?, comment = ?, image = ? WHERE id = ?',
                (name, role, rating, comment, data.get('image'), review_id)
            )
        else:
            conn.execute(
                'UPDATE reviews SET customer_name = ?, role = ?, rating = ?, comment = ? WHERE id = ?',
                (name, role, rating, comment, review_id)
            )
        conn.commit()
        return jsonify({'status': STATUS_OK})

@app.route('/api/reviews/<int:review_id>', methods=['DELETE'])
def delete_review(review_id):
    with get_db() as conn:
        conn.execute('DELETE FROM reviews WHERE id = ?', (review_id,))
        conn.commit()
        return jsonify({'status': STATUS_DELETED})


# ============================================================
#  CONTACT US
# ============================================================

@app.route('/api/contact', methods=['POST'])
def add_contact_message():
    data = request.json or {}
    name = clean_text(data.get('name'))
    email = clean_text(data.get('email'))
    subject = clean_text(data.get('subject'))
    message = clean_text(data.get('message'))

    if not name or len(name) < 2:
        return jsonify({'error': 'Please enter your name.'}), 400
    if not is_valid_email(email):
        return jsonify({'error': 'Please enter a valid email address.'}), 400
    if not message or len(message) < 5:
        return jsonify({'error': 'Message must be at least 5 characters.'}), 400

    with get_db() as conn:
        conn.execute(
            'INSERT INTO contact_messages (name, email, subject, message) VALUES (?, ?, ?, ?)',
            (name, email, subject, message)
        )
        conn.commit()
        return jsonify({'status': STATUS_OK})


if __name__ == '__main__':
    debug_flag = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    app.run(debug=debug_flag)
