from flask import Flask, render_template, request, redirect, url_for, session, Response, jsonify, flash
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_  # For aggregating and search filtering
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from abc import ABC, abstractmethod

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

# Base Model class for inheritance and common functionality
class BaseModel(db.Model):
    __abstract__ = True

    def save(self):
        """Save the instance to the database."""
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """Delete the instance from the database."""
        db.session.delete(self)
        db.session.commit()

    @classmethod
    def get_by_id(cls, id):
        """Get instance by ID."""
        return cls.query.get(id)

    @classmethod
    def get_all(cls):
        """Get all instances."""
        return cls.query.all()

    def to_dict(self):
        """Convert model to dictionary (to be overridden by subclasses)."""
        return {}

# Abstract base class for inventory operations
class InventoryOperation(ABC):
    @abstractmethod
    def execute(self):
        """Execute the inventory operation."""
        pass

    @abstractmethod
    def validate(self):
        """Validate the operation before execution."""
        pass

    @abstractmethod
    def get_report_data(self):
        """Get data for reporting purposes."""
        pass

# New Supplier model (supplierId as string, auto-increments as SUP001, etc.)
class Supplier(BaseModel):
    __tablename__ = 'supplier'
    supplierId = db.Column(db.String(10), primary_key=True)  # String primary key
    _name = db.Column(db.String(120), nullable=False)
    _contact = db.Column(db.String(120), nullable=False)
    _address = db.Column(db.Text, nullable=False)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Name cannot be empty")
        self._name = value.strip()

    @property
    def contact(self):
        return self._contact

    @contact.setter
    def contact(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Contact cannot be empty")
        self._contact = value.strip()

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Address cannot be empty")
        self._address = value.strip()

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

    def to_dict(self):
        return {
            'supplierId': self.supplierId,
            'name': self.name,
            'contact': self.contact,
            'address': self.address,
            'totalPurchases': self.get_total_purchases()
        }

    def __repr__(self):
        return f'<Supplier {self.supplierId}>'

# Base Transaction model with polymorphism
class Transaction(db.Model):
    __tablename__ = 'transaction'
    transId = db.Column(db.String(20), primary_key=True)  # e.g., TXN001
    type = db.Column(db.String(20), nullable=False)  # receive, issue, transfer, adjustment
    date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    userId = db.Column(db.String(10), db.ForeignKey('users.userId'), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    supplierId = db.Column(db.String(10), db.ForeignKey('supplier.supplierId'), nullable=True)  # For receive
    itemSku = db.Column(db.String(80), db.ForeignKey('items_list.sku'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'transaction'
    }

    items_list = db.relationship('ItemsList', foreign_keys=[itemSku], backref='transactions')

    @classmethod
    def get_next_trans_id(cls):
        max_trans = db.session.query(func.max(cls.transId)).scalar()
        if max_trans:
            num = int(max_trans[3:]) + 1
        else:
            num = 1
        return f'TXN{num:03d}'

    def apply_transaction(self, item):
        """Abstract method to apply transaction effects on item stock. To be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement apply_transaction method")

    def __repr__(self):
        return f'<Transaction {self.transId}>'

# Receive Transaction subclass
class ReceiveTransaction(Transaction):
    __mapper_args__ = {
        'polymorphic_identity': 'receive'
    }

    def apply_transaction(self, item):
        """Increase stock for receive transactions."""
        item.totalStock += self.quantity

# Issue Transaction subclass
class IssueTransaction(Transaction):
    __mapper_args__ = {
        'polymorphic_identity': 'issue'
    }

    def apply_transaction(self, item):
        """Decrease stock for issue transactions."""
        item.totalStock -= self.quantity

# Transfer Transaction subclass
class TransferTransaction(Transaction):
    __mapper_args__ = {
        'polymorphic_identity': 'transfer'
    }

    def apply_transaction(self, item):
        """Decrease stock for transfer transactions (assuming transfer out)."""
        item.totalStock -= self.quantity

# Adjustment Transaction subclass
class AdjustmentTransaction(Transaction):
    __mapper_args__ = {
        'polymorphic_identity': 'adjustment'
    }

    def apply_transaction(self, item):
        """Adjust stock for adjustment transactions (could be positive or negative)."""
        # For adjustments, quantity can be positive (add) or negative (subtract)
        item.totalStock += self.quantity

# Model definition (supplierId as string)
class ItemsList(BaseModel):
    sku = db.Column(db.String(80), primary_key=True)
    _name = db.Column(db.String(120), nullable=False)
    _description = db.Column(db.Text, nullable=True)
    _unit = db.Column(db.String(50), nullable=False)
    _reorderPoint = db.Column(db.Integer, nullable=False)
    _supplierId = db.Column(db.String(10), nullable=False)  # String to match Supplier
    _totalStock = db.Column(db.Integer, nullable=False, default=0)  # Added for Total Stock

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Name cannot be empty")
        self._name = value.strip()

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value.strip() if value else None

    @property
    def unit(self):
        return self._unit

    @unit.setter
    def unit(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Unit cannot be empty")
        self._unit = value.strip()

    @property
    def reorderPoint(self):
        return self._reorderPoint

    @reorderPoint.setter
    def reorderPoint(self, value):
        if value < 0:
            raise ValueError("Reorder point cannot be negative")
        self._reorderPoint = value

    @property
    def supplierId(self):
        return self._supplierId

    @supplierId.setter
    def supplierId(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Supplier ID cannot be empty")
        self._supplierId = value.strip()

    @property
    def totalStock(self):
        return self._totalStock

    @totalStock.setter
    def totalStock(self, value):
        if value < 0:
            raise ValueError("Total stock cannot be negative")
        self._totalStock = value

    @classmethod
    def get_next_sku(cls):
        # Get the max sku, extract number, increment, and format
        max_sku = db.session.query(func.max(cls.sku)).scalar()
        if max_sku:
            num = int(max_sku[3:]) + 1  # Extract number after "SKU"
        else:
            num = 1
        return f'SKU{num:03d}'

    def to_dict(self):
        return {
            'sku': self.sku,
            'name': self.name,
            'description': self.description,
            'unit': self.unit,
            'totalStock': self.totalStock,
            'reorderPoint': self.reorderPoint,
            'supplierId': self.supplierId,
            'status': 'In Stock' if self.totalStock > self.reorderPoint else 'Low Stock'
        }

    def __repr__(self):
        return f'<SKU {self.sku}>'

# New User model (userId as string, auto-increments as USER001, etc.)
class User(BaseModel):
    __tablename__ = 'users'
    userId = db.Column(db.String(10), primary_key=True)  # String primary key
    _username = db.Column(db.String(80), unique=True, nullable=False)
    _fullName = db.Column(db.String(120), nullable=False)
    _password = db.Column(db.String(255), nullable=False)  # Hashed password
    _role = db.Column(db.String(50), nullable=False)  # e.g., 'admin' or 'staff'

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Username cannot be empty")
        self._username = value.strip()

    @property
    def fullName(self):
        return self._fullName

    @fullName.setter
    def fullName(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Full name cannot be empty")
        self._fullName = value.strip()

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Password cannot be empty")
        self._password = value.strip()

    @property
    def role(self):
        return self._role

    @role.setter
    def role(self, value):
        if value not in ['admin', 'staff']:
            raise ValueError("Role must be 'admin' or 'staff'")
        self._role = value

    @classmethod
    def get_next_id(cls):
        # Get the max userId, extract number, increment, and format
        max_user = db.session.query(func.max(cls.userId)).scalar()
        if max_user:
            num = int(max_user[4:]) + 1  # Extract number after "USER"
        else:
            num = 1
        return f'USER{num:03d}'

    def to_dict(self):
        return {
            'userId': self.userId,
            'username': self.username,
            'fullName': self.fullName,
            'role': self.role.upper()
        }

    def __repr__(self):
        return f'<User {self.userId}>'

# New Location model
class Location(BaseModel):
    __tablename__ = 'location'
    locationId = db.Column(db.String(10), primary_key=True)
    _warehouseId = db.Column(db.String(10), nullable=False)
    _aisle = db.Column(db.String(10), nullable=False)
    _rack = db.Column(db.String(10), nullable=False)
    _shelf = db.Column(db.String(10), nullable=False)
    _capacity = db.Column(db.Integer, nullable=False)

    @property
    def warehouseId(self):
        return self._warehouseId

    @warehouseId.setter
    def warehouseId(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Warehouse ID cannot be empty")
        self._warehouseId = value.strip()

    @property
    def aisle(self):
        return self._aisle

    @aisle.setter
    def aisle(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Aisle cannot be empty")
        self._aisle = value.strip()

    @property
    def rack(self):
        return self._rack

    @rack.setter
    def rack(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Rack cannot be empty")
        self._rack = value.strip()

    @property
    def shelf(self):
        return self._shelf

    @shelf.setter
    def shelf(self, value):
        if not value or len(value.strip()) == 0:
            raise ValueError("Shelf cannot be empty")
        self._shelf = value.strip()

    @property
    def capacity(self):
        return self._capacity

    @capacity.setter
    def capacity(self, value):
        if value <= 0:
            raise ValueError("Capacity must be positive")
        self._capacity = value

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

    def to_dict(self):
        return {
            'locationId': self.locationId,
            'warehouseId': self.warehouseId,
            'aisle': self.aisle,
            'rack': self.rack,
            'shelf': self.shelf,
            'fullPath': self.fullPath,
            'capacity': self.capacity
        }

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
        if role == 'admin':
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('dashboard_staff'))

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
            print(f"Login successful: user={user.username}, role={user.role}, first_name={session['first_name']}")
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('dashboard_staff'))
        else:
            print(f"Login failed: email={email}")
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
        'capacity': location.capacity
    } for location in locations]
    return render_template('LocationsPage.html', location_list=location_list, first_name=session['first_name'], role=session['role'])

@app.route('/transactions')
def transactions():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('TransactionsPage.html', first_name=session['first_name'], role=session['role'], userId=session['userId'])

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
        'capacity': location.capacity
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
        'capacity': location.capacity
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
        'supplierId': trans.supplierId
    } for trans in transactions])

@app.route('/api/transactions', methods=['POST'])
def add_transaction():
    if 'first_name' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    trans_type = data['type']
    user_id = data['userId']  # Assuming from session or data

    # Fetch the item to update stock
    item = ItemsList.query.get_or_404(data['itemSku'])

    # Instantiate the appropriate transaction subclass based on type
    if trans_type == 'receive':
        new_trans = ReceiveTransaction(
            transId=Transaction.get_next_trans_id(),
            userId=user_id,
            notes=data.get('notes'),
            itemSku=data['itemSku'],
            quantity=data['quantity'],
            supplierId=data.get('supplierId')
        )
    elif trans_type == 'issue':
        new_trans = IssueTransaction(
            transId=Transaction.get_next_trans_id(),
            userId=user_id,
            notes=data.get('notes'),
            itemSku=data['itemSku'],
            quantity=data['quantity']
        )
    elif trans_type == 'transfer':
        new_trans = TransferTransaction(
            transId=Transaction.get_next_trans_id(),
            userId=user_id,
            notes=data.get('notes'),
            itemSku=data['itemSku'],
            quantity=data['quantity']
        )
    elif trans_type == 'adjustment':
        new_trans = AdjustmentTransaction(
            transId=Transaction.get_next_trans_id(),
            userId=user_id,
            notes=data.get('notes'),
            itemSku=data['itemSku'],
            quantity=data['quantity']
        )
    else:
        return jsonify({'error': 'Invalid transaction type'}), 400

    # Apply the transaction polymorphically
    new_trans.apply_transaction(item)

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

@app.route('/dashboard-staff')
def dashboard_staff():
    if 'first_name' not in session:
        return redirect(url_for('login'))

    try:
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

        return render_template('DashboardPageStaff.html',
                               first_name=session['first_name'],
                               role=session['role'],
                               total_items=total_items,
                               low_stock_items=low_stock_items,
                               todays_transactions=todays_transactions,
                               active_locations=active_locations,
                               recent_activity=recent_activity)
    except Exception as e:
        print(f"Database error in dashboard_staff: {e}")
        # Return a basic template or error page
        return render_template('DashboardPageStaff.html',
                               first_name=session['first_name'],
                               role=session['role'],
                               total_items=0,
                               low_stock_items=0,
                               todays_transactions=0,
                               active_locations=0,
                               recent_activity=[])

@app.route('/items-staff')
def items_staff():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('ItemsPageStaff.html', first_name=session['first_name'], role=session['role'])

@app.route('/locations-staff')
def locations_staff():
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
        'capacity': location.capacity
    } for location in locations]
    return render_template('LocationsPageStaff.html', location_list=location_list, first_name=session['first_name'], role=session['role'])

@app.route('/transactions-staff')
def transactions_staff():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('TransactionsPageStaff.html', first_name=session['first_name'], role=session['role'], userId=session['userId'])

@app.route('/suppliers-staff')
def suppliers_staff():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    supplier_list = Supplier.query.all()
    return render_template('SuppliersPageStaff.html', supplier_list=supplier_list, first_name=session['first_name'], role=session['role'])

@app.route('/reports-staff')
def reports_staff():
    if 'first_name' not in session:
        return redirect(url_for('login'))
    return render_template('ReportsPageStaff.html', first_name=session['first_name'], role=session['role'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates tables based on models if they don't exist
    app.run(debug=True)
