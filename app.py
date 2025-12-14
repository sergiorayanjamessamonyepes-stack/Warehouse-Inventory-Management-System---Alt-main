from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_  # For aggregating and search filtering
import pymysql
import mysql.connector

def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Dreakmaaram123",
        database="flask_app"
    )

app = Flask(__name__, template_folder='Warehouse-Inventory-Management-System---Alt-main/templates')

ADMIN_CODE = "SECRET123"

# App configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Dreakmaaram123@localhost/flask_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Recommended to avoid warnings

db = SQLAlchemy(app)

# New Supplier model (supplierId as string, auto-increments as SUP001, etc.)
class Supplier(db.Model):
    __tablename__ = 'supplier'
    supplierId = db.Column(db.String(10), primary_key=True)  # String primary key
    name = db.Column(db.String(120), nullable=False)
    contact = db.Column(db.String(120), nullable=False)
    address = db.Column(db.Text, nullable=False)

    @classmethod
    def get_next_id(cls):
        # Get the max supplierId, extract number, increment, and format
        max_supplier = db.session.query(func.max(cls.supplierId)).scalar()
        if max_supplier:
            num = int(max_supplier[3:]) + 1  # Extract number after "SUP"
        else:
            num = 1
        return f'SUP{num:03d}'

    def get_total_purchases(self):
        # Calculate total purchases from transactions (sum of quantities for receive transactions)
        total = db.session.query(func.sum(Transaction.quantity)).filter(Transaction.supplierId == self.supplierId, Transaction.type == 'receive').scalar()
        return total or 0

    def __repr__(self):
        return f'<Supplier {self.supplierId}>'

# Updated Transaction model (simplified to one item per transaction, transId as primary key)
class Transaction(db.Model):
    __tablename__ = 'transaction'
    transId = db.Column(db.String(20), primary_key=True)  # e.g., TXN001
    type = db.Column(db.String(20), nullable=False)  # receive, issue, transfer, adjustment
    date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    userId = db.Column(db.String(10), db.ForeignKey('users.userId'), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    supplierId = db.Column(db.String(10), db.ForeignKey('supplier.supplierId'), nullable=True)  # For receive
    fromLocationId = db.Column(db.String(10), nullable=True)  # For transfer
    toLocationId = db.Column(db.String(10), nullable=True)  # For transfer
    reason = db.Column(db.String(255), nullable=True)  # For adjustment
    itemSku = db.Column(db.String(80), db.ForeignKey('items_list.sku'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    locationId = db.Column(db.String(10), nullable=False)  # Location where transaction occurred

    @classmethod
    def get_next_trans_id(cls):
        max_trans = db.session.query(func.max(cls.transId)).scalar()
        if max_trans:
            num = int(max_trans[3:]) + 1
        else:
            num = 1
        return f'TXN{num:03d}'

    def __repr__(self):
        return f'<Transaction {self.transId}>'

# Model definition (supplierId as string)
class ItemsList(db.Model):
    sku = db.Column(db.String(80), primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    unit = db.Column(db.String(50), nullable=False)
    reorderPoint = db.Column(db.Integer, nullable=False)
    supplierId = db.Column(db.String(10), nullable=False)  # String to match Supplier
    totalStock = db.Column(db.Integer, nullable=False, default=0)  # Added for Total Stock

    @classmethod
    def get_next_sku(cls):
        # Get the max sku, extract number, increment, and format
        max_sku = db.session.query(func.max(cls.sku)).scalar()
        if max_sku:
            num = int(max_sku[3:]) + 1  # Extract number after "SKU"
        else:
            num = 1
        return f'SKU{num:03d}'

    def __repr__(self):
        return f'<SKU {self.sku}>'

# New User model (userId as string, auto-increments as USER001, etc.)
class User(db.Model):
    __tablename__ = 'users'
    userId = db.Column(db.String(10), primary_key=True)  # String primary key
    username = db.Column(db.String(80), unique=True, nullable=False)
    fullName = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Plain-text for now; hash in production
    role = db.Column(db.String(50), nullable=False)  # e.g., 'admin' or 'staff'

    @classmethod
    def get_next_id(cls):
        # Get the max userId, extract number, increment, and format
        max_user = db.session.query(func.max(cls.userId)).scalar()
        if max_user:
            num = int(max_user[4:]) + 1  # Extract number after "USER"
        else:
            num = 1
        return f'USER{num:03d}'

    def __repr__(self):
        return f'<User {self.userId}>'

# New Location model
class Location(db.Model):
    __tablename__ = 'location'
    locationId = db.Column(db.String(10), primary_key=True)
    warehouseId = db.Column(db.String(10), nullable=False)
    aisle = db.Column(db.String(10), nullable=False)
    rack = db.Column(db.String(10), nullable=False)
    shelf = db.Column(db.String(10), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)

    @classmethod
    def get_next_id(cls):
        # Get the max locationId, extract number, increment, and format
        max_location = db.session.query(func.max(cls.locationId)).scalar()
        if max_location:
            num = int(max_location[3:]) + 1  # Extract number after "LOC"
        else:
            num = 1
        return f'LOC{num:03d}'

    def getFullPath(self):
        return f"{self.warehouseId}-{self.aisle}-{self.rack}-{self.shelf}"

    def getCurrentStock(self):
        # Calculate current stock from transactions (sum of quantities for receive minus issue at this location)
        receive = db.session.query(func.sum(Transaction.quantity)).filter(Transaction.locationId == self.locationId, Transaction.type == 'receive').scalar() or 0
        issue = db.session.query(func.sum(Transaction.quantity)).filter(Transaction.locationId == self.locationId, Transaction.type == 'issue').scalar() or 0
        return receive - issue

    def __repr__(self):
        return f'<Location {self.locationId}>'
@app.route('/')
def landingpage():
    return render_template('LandingPage.html')

@app.route('/home')
def home():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('HomePage.html', first_name=session['first_name'], role=session['role'])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        admin_code = request.form.get('admin_code', '')

        role = "admin" if admin_code == ADMIN_CODE else "user"

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (first_name, last_name, email, password, role) VALUES (%s, %s, %s, %s, %s)",
            (first_name, last_name, email, password, role)
        )
        conn.commit()
        cursor.close()
        conn.close()

        session['first_name'] = first_name
        session['role'] = role

        # Redirect based on role
        return redirect(url_for('admin_dashboard' if role == 'admin' else 'home'))

    return render_template('SignUpPage.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            session['first_name'] = user['first_name']
            session['role'] = user['role']

            # Redirect based on role
            return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'home'))

        return "Invalid email or password"

    return render_template('LoginPage.html')

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landingpage'))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # Drop all tables
        db.create_all()  # Creates tables based on models
    app.run(debug=True)
