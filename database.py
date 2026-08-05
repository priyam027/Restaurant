import sqlite3
from werkzeug.security import generate_password_hash

def get_db():
    conn = sqlite3.connect('restaurant.db')
    conn.row_factory = sqlite3.Row   # lets us access columns by name, e.g. row['name']
    return conn

def _add_column_if_missing(conn, table, column, coltype):
    """Safely adds a column to an existing table without wiping existing data."""
    existing = [row['name'] for row in conn.execute(f'PRAGMA table_info({table})').fetchall()]
    if column not in existing:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {coltype}')

def init_db():
    conn = get_db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS food (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        category_id INTEGER,
        image TEXT,
        FOREIGN KEY (category_id) REFERENCES categories(id)
    );

    CREATE TABLE IF NOT EXISTS offers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        image TEXT
    );

    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        date TEXT,
        time TEXT,
        guests INTEGER,
        message TEXT,
        status TEXT DEFAULT 'pending'
    );

    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_name TEXT,
        rating INTEGER,
        comment TEXT
    );

    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT,
        message TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # ---- Migrations: add new columns to existing tables without losing data ----
    _add_column_if_missing(conn, 'categories', 'description', 'TEXT')
    _add_column_if_missing(conn, 'categories', 'price', 'REAL')
    _add_column_if_missing(conn, 'categories', 'image', 'TEXT')

    _add_column_if_missing(conn, 'offers', 'badge', 'TEXT')

    _add_column_if_missing(conn, 'reviews', 'image', 'TEXT')
    _add_column_if_missing(conn, 'reviews', 'role', 'TEXT')

    conn.commit()

    # ---- Seed a default admin login if none exists yet ----
    existing_admin = conn.execute('SELECT id FROM admin_users LIMIT 1').fetchone()
    if not existing_admin:
        conn.execute(
            'INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
            ('admin', generate_password_hash('Admin_@123'))
        )
        conn.commit()
        print("Default admin created -> username: admin | password: Admin_@123")

    # ---- Seed a few sample rows so the new pages aren't empty on first run ----
    if not conn.execute('SELECT id FROM categories LIMIT 1').fetchone():
        conn.executemany(
            'INSERT INTO categories (name, description, price, image) VALUES (?, ?, ?, ?)',
            [
                ('Paneer Handi', 'Soft paneer cubes cooked in a rich, creamy tomato gravy with aromatic Indian spices.', 20.00, 'image/indian.jpg.png'),
                ('Pizza', 'Hand-tossed dough, fire-baked to smoky perfection.', 12.99, 'image/pizza.jpg.png'),
                ('Burger', 'Juicy grilled patty stacked with fresh toppings.', 9.49, 'image/burger.jpg.png'),
                ('Pasta', 'Creamy, rich sauces tossed with al dente pasta.', 11.25, 'image/pasta.jpg.png'),
                ('Chinese', 'Wok-fired classics bursting with bold flavor.', 13.99, 'image/chinese.jpg.png'),
                ('Indian', 'Aromatic spices simmered low and slow.', 10.75, 'image/indian.jpg.png'),
                ('Desserts', 'Sweet, indulgent finishes to every meal.', 6.50, 'image/dessert.jpg.png'),
            ]
        )
        conn.commit()

    if not conn.execute('SELECT id FROM offers LIMIT 1').fetchone():
        conn.executemany(
            'INSERT INTO offers (title, description, image, badge) VALUES (?, ?, ?, ?)',
            [
                ('Weekend Family Combo', 'Enjoy 25% off on all family combo meals this weekend.', 'image/offer1.jpg.png', '25% OFF'),
                ('Pizza Night Special', 'Buy any large pizza and get a second one free, every Tuesday.', 'image/offer2.jpg.png', 'Buy 1 Get 1'),
                ('Dessert Delight', '15% off all desserts when you dine in with us.', 'image/offer3.jpg.png', '15% OFF'),
            ]
        )
        conn.commit()

    if not conn.execute('SELECT id FROM reviews LIMIT 1').fetchone():
        conn.executemany(
            'INSERT INTO reviews (customer_name, role, rating, comment, image) VALUES (?, ?, ?, ?, ?)',
            [
                ('Hitrajsinh Gohil', 'Food Blogger', 5, 'The wood-fired pizza was absolutely incredible, and the staff made us feel right at home. Best Italian food in town!', 'image/Hitraj.jpeg'),
                ('Priyam Maniya', 'Regular Customer', 5, 'We celebrated our anniversary here and it was perfect. Cozy ambience, generous portions, and the pasta was so creamy and rich.', 'image/pm.jpeg'),
                ('Ved Desai', 'Local Guide', 5, 'Booking a table online was quick and easy, and the dessert platter is a must-try. Will definitely be coming back with family!', 'image/ved.jpeg'),
            ]
        )
        conn.commit()

    conn.close()

if __name__ == '__main__':
    init_db()
    print("Database ready: restaurant.db")
