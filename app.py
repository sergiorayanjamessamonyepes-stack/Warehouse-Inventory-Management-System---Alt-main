from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify, flash
from functools import wraps

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_  # For aggregating and search filtering
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Set a unique and secret key for sessions

ADMIN_CODE = "SECRET123"

# App configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Dreakmaaram123@localhost/flask_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Recommended to avoid warnings

db = SQLAlchemy(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'first_name' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'first_name' not in session or session['role'] != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

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

    items_list = db.relationship('ItemsList', foreign_keys=[itemSku], backref='transactions')

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
    password = db.Column(db.String(255), nullable=False)  # Hashed password
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

    @property
    def fullPath(self):
        return f"{self.warehouseId}-{self.aisle}-{self.rack}-{self.shelf}"

    @property
    def currentStock(self):
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

        role = "admin" if admin_code == ADMIN_CODE else "staff"

        hashed_password = generate_password_hash(password)

        new_user = User(
            userId=User.get_next_id(),
            username=email,
            fullName=f"{first_name} {last_name}",
            password=hashed_password,
            role=role
        )

        db.session.add(new_user)
        db.session.commit()

        session['first_name'] = first_name
        session['role'] = role

        # Redirect based on role
        return redirect(url_for('dashboard'))

    return render_template('SignUpPage.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(username=email).first()

        if user and check_password_hash(user.password, password):
            session['first_name'] = user.fullName.split()[0]  # Assuming first name is first part
            session['role'] = user.role
            session['userId'] = user.userId
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

    return render_template('LoginPage.html')

# Logout Route
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'first_name' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    return render_template('HomePage.html', first_name=session['first_name'], role=session['role'])

@app.route('/dashboard')
def dashboard():
    if 'first_name' not in session:
        return redirect(url_for('login'))

    # Query stats
    total_items = ItemsList.query.count()
    low_stock_items = ItemsList.query.filter(ItemsList.totalStock <= ItemsList.reorderPoint).count()
    todays_transactions = Transaction.query.filter(func.date(Transaction.date) == date.today()).count()
    active_locations = Location.query.count()

    # Recent activity: fetch last 5 transactions with item names
    recent_transactions = Transaction.query.join(ItemsList, Transaction.itemSku == ItemsList.sku).order_by(Transaction.date.desc()).limit(5).all()

    # Format recent activity
    recent_activity = []
    for trans in recent_transactions:
        # Calculate time ago
        time_diff = datetime.now() - trans.date
        if time_diff.days > 0:
            time_ago = f"{time_diff.days} days ago"
        elif time_diff.seconds // 3600 > 0:
            time_ago = f"{time_diff.seconds // 3600} hours ago"
        else:
            time_ago = f"{time_diff.seconds // 60} minutes ago"

        # Map type to description
        type_desc = {
            'receive': 'Stock received',
            'issue': 'Stock issued',
            'transfer': 'Stock transferred',
            'adjustment': 'Stock adjusted'
        }.get(trans.type, trans.type)

        recent_activity.append({
            'type': type_desc,
            'item_name': trans.items_list.name,
            'quantity': trans.quantity,
            'time_ago': time_ago
        })

    return render_template('DashboardPage.html',
                           first_name=session['first_name'],
                           role=session['role'],
                           total_items=total_items,
                           low_stock_items=low_stock_items,
                           todays_transactions=todays_transactions,
                           active_locations=active_locations,
                           recent_activity=recent_activity)

@app.route('/items')
def items():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('ItemsPage.html', first_name=session['first_name'], role=session['role'])

@app.route('/locations')
def locations():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    locations = Location.query.all()
    location_list = [{
        'locationId': location.locationId,
        'warehouseId': location.warehouseId,
        'aisle': location.aisle,
        'rack': location.rack,
        'shelf': location.shelf,
        'fullPath': location.fullPath,
        'capacity': location.capacity,
        'currentStock': location.currentStock
    } for location in locations]
    return render_template('LocationsPage.html', location_list=location_list, first_name=session['first_name'], role=session['role'])

@app.route('/transactions')
def transactions():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('TransactionsPage.html', first_name=session['first_name'], role=session['role'])

@app.route('/suppliers')
def suppliers():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    supplier_list = Supplier.query.all()
    return render_template('SuppliersPage.html', supplier_list=supplier_list, first_name=session['first_name'], role=session['role'])

@app.route('/reports')
def reports():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('ReportsPage.html', first_name=session['first_name'], role=session['role'])

@app.route('/users')
def users():
    if 'first_name' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    return render_template('UsersPage.html', first_name=session['first_name'], role=session['role'])

@app.route('/item/<sku>')
def item_details(sku):
    if 'first_name' not in session:
        return redirect(url_for('login'))
    item = ItemsList.query.get_or_404(sku)
    return render_template('ItemPage.html', item=item)

@app.route('/api/items', methods=['GET'])
@login_required
def get_items():
    items = ItemsList.query.all()
    return jsonify([{
        'sku': item.sku,
        'name': item.name,
        'description': item.description,
        'unit': item.unit,
        'totalStock': item.totalStock,
        'reorderPoint': item.reorderPoint,
        'supplierId': item.supplierId,
        'status': 'In Stock' if item.totalStock > item.reorderPoint else 'Low Stock'
    } for item in items])

@app.route('/api/items', methods=['POST'])
@login_required
def add_item():
    data = request.get_json()
    new_item = ItemsList(
        sku=ItemsList.get_next_sku(),
        name=data['name'],
        description=data.get('description'),
        unit=data['unit'],
        totalStock=data['totalStock'],
        reorderPoint=data['reorderPoint'],
        supplierId=data['supplierId']
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify({'message': 'Item added successfully'}), 201

@app.route('/api/items/<sku>', methods=['PUT'])
@login_required
def update_item(sku):
    data = request.get_json()
    item = ItemsList.query.get_or_404(sku)
    item.name = data['name']
    item.description = data.get('description')
    item.unit = data['unit']
    item.totalStock = data['totalStock']
    item.reorderPoint = data['reorderPoint']
    item.supplierId = data['supplierId']
    db.session.commit()
    return jsonify({'message': 'Item updated successfully'})

@app.route('/api/items/<sku>', methods=['DELETE'])
@login_required
def delete_item(sku):
    item = ItemsList.query.get_or_404(sku)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Item deleted successfully'})

@app.route('/api/items/search', methods=['GET'])
@login_required
def search_items():
    query = request.args.get('q', '')
    items = ItemsList.query.filter(
        or_(ItemsList.name.contains(query), ItemsList.sku.contains(query))
    ).all()
    return jsonify([{
        'sku': item.sku,
        'name': item.name,
        'description': item.description,
        'unit': item.unit,
        'totalStock': item.totalStock,
        'reorderPoint': item.reorderPoint,
        'supplierId': item.supplierId,
        'status': 'In Stock' if item.totalStock > item.reorderPoint else 'Low Stock'
    } for item in items])

@app.route('/api/locations', methods=['GET'])
@login_required
def get_locations():
    locations = Location.query.all()
    return jsonify([{
        'locationId': location.locationId,
        'warehouseId': location.warehouseId,
        'aisle': location.aisle,
        'rack': location.rack,
        'shelf': location.shelf,
        'fullPath': location.fullPath,
        'capacity': location.capacity,
        'currentStock': location.currentStock
    } for location in locations])

@app.route('/api/locations', methods=['POST'])
@login_required
def add_location():
    data = request.get_json()
    new_location = Location(
        locationId=Location.get_next_id(),
        warehouseId=data['warehouseId'],
        aisle=data['aisle'],
        rack=data['rack'],
        shelf=data['shelf'],
        capacity=data['capacity']
    )
    db.session.add(new_location)
    db.session.commit()
    return jsonify({'message': 'Location added successfully'}), 201

@app.route('/api/locations/search', methods=['GET'])
@login_required
def search_locations():
    query = request.args.get('q', '')
    locations = Location.query.filter(
        or_(Location.locationId.contains(query), Location.warehouseId.contains(query), Location.aisle.contains(query))
    ).all()
    return jsonify([{
        'locationId': location.locationId,
        'warehouseId': location.warehouseId,
        'aisle': location.aisle,
        'rack': location.rack,
        'shelf': location.shelf,
        'fullPath': location.fullPath,
        'capacity': location.capacity,
        'currentStock': location.currentStock
    } for location in locations])

@app.route('/api/suppliers', methods=['GET'])
def get_suppliers():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    suppliers = Supplier.query.all()
    return jsonify([{
        'supplierId': supplier.supplierId,
        'name': supplier.name,
        'contact': supplier.contact,
        'address': supplier.address,
        'totalPurchases': supplier.get_total_purchases()
    } for supplier in suppliers])

@app.route('/api/suppliers', methods=['POST'])
def add_supplier():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        data = request.get_json()
        new_supplier = Supplier(
            supplierId=Supplier.get_next_id(),
            name=data['name'],
            contact=data['contact'],
            address=data['address']
        )
        db.session.add(new_supplier)
        db.session.commit()
        return jsonify({'message': 'Supplier added successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    if 'first_name' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    users = User.query.all()
    return jsonify([{
        'userId': user.userId,
        'username': user.username,
        'fullName': user.fullName,
        'role': user.role.upper()
    } for user in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    if 'first_name' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        userId=User.get_next_id(),
        username=data['username'],
        fullName=data['fullName'],
        password=hashed_password,
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User added successfully', 'userId': new_user.userId}), 201

@app.route('/api/users/<userId>', methods=['PUT'])
def update_user(userId):
    if 'first_name' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    user = User.query.get_or_404(userId)
    user.username = data['username']
    user.fullName = data['fullName']
    if data.get('password'):
        user.password = generate_password_hash(data['password'])
    user.role = data['role']
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route('/api/users/<userId>', methods=['DELETE'])
def delete_user(userId):
    if 'first_name' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get_or_404(userId)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/users/search', methods=['GET'])
def search_users():
    if 'first_name' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    query = request.args.get('q', '')
    users = User.query.filter(
        or_(User.username.contains(query), User.fullName.contains(query))
    ).all()
    return jsonify([{
        'userId': user.userId,
        'username': user.username,
        'fullName': user.fullName,
        'role': user.role.upper()
    } for user in users])

@app.route('/api/suppliers/search', methods=['GET'])
def search_suppliers():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    query = request.args.get('q', '')
    suppliers = Supplier.query.filter(
        or_(Supplier.name.contains(query), Supplier.supplierId.contains(query))
    ).all()
    return jsonify([{
        'supplierId': supplier.supplierId,
        'name': supplier.name,
        'contact': supplier.contact,
        'address': supplier.address,
        'totalPurchases': supplier.get_total_purchases()
    } for supplier in suppliers])

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    transactions = Transaction.query.all()
    return jsonify([{
        'transId': trans.transId,
        'type': trans.type,
        'date': trans.date.isoformat(),
        'userId': trans.userId,
        'itemSku': trans.itemSku,
        'quantity': trans.quantity,
        'notes': trans.notes,
        'supplierId': trans.supplierId,
        'fromLocationId': trans.fromLocationId,
        'toLocationId': trans.toLocationId,
        'reason': trans.reason,
        'locationId': trans.locationId
    } for trans in transactions])

@app.route('/api/transactions', methods=['POST'])
def add_transaction():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    trans_type = data['type']
    user_id = data['userId']  # Assuming from session or data

    new_trans = Transaction(
        transId=Transaction.get_next_trans_id(),
        type=trans_type,
        userId=user_id,
        notes=data.get('notes'),
        itemSku=data['itemSku'],
        quantity=data['quantity']
    )

    if trans_type == 'receive':
        new_trans.supplierId = data.get('supplierId')
        new_trans.locationId = data['locationId']
    elif trans_type == 'transfer':
        new_trans.fromLocationId = data['fromLocationId']
        new_trans.toLocationId = data['toLocationId']
        new_trans.locationId = data['fromLocationId']  # As per JS
    elif trans_type == 'issue':
        new_trans.locationId = data['locationId']
    elif trans_type == 'adjustment':
        new_trans.reason = data.get('reason')
        new_trans.locationId = data['locationId']

    db.session.add(new_trans)
    db.session.commit()
    return jsonify({'message': 'Transaction added successfully', 'transId': new_trans.transId}), 201

@app.route('/api/reports/low-stock', methods=['GET'])
def get_low_stock_report():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    items = ItemsList.query.filter(ItemsList.totalStock <= ItemsList.reorderPoint).all()
    return jsonify([{
        'sku': item.sku,
        'name': item.name,
        'totalStock': item.totalStock,
        'reorderPoint': item.reorderPoint,
        'supplierId': item.supplierId,
        'status': 'Low Stock'
    } for item in items])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates tables based on models if they don't exist
    app.run(debug=True)
