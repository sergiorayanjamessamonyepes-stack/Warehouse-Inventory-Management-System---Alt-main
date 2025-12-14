from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_  # For aggregating and search filtering

app = Flask(__name__)

# App configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Dreakmaaram123@localhost/flask_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Recommended to avoid warnings

db = SQLAlchemy(app)

# New Supplier model (supplierId as string, auto-increments as SUP001, etc.)
class Supplier(db.Model):
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
    transId = db.Column(db.String(20), primary_key=True)  # e.g., TXN001
    type = db.Column(db.String(20), nullable=False)  # receive, issue, transfer, adjustment
    date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    userId = db.Column(db.String(10), db.ForeignKey('user.userId'), nullable=False)
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

# Route for the main layout (serves ItemsPage.html)
@app.route('/')
def index():
    return render_template('DashboardPage.html')

# Routes for each page (return partial HTML for dynamic loading)
@app.route('/dashboard')
def dashboard():
    return render_template('DashboardPage.html')

@app.route('/items')
def items():
    items = ItemsList.query.all()
    items_data = [{
        'sku': item.sku,
        'name': item.name,
        'description': item.description,
        'unit': item.unit,
        'totalStock': item.totalStock,
        'reorderPoint': item.reorderPoint,
        'supplierId': item.supplierId,
        'status': 'In Stock' if item.totalStock > item.reorderPoint else 'Low Stock'
    } for item in items]
    return render_template('ItemsPage.html', items=items_data)

@app.route('/locations')
def locations():
    locations = Location.query.all()
    locations_data = [{
        'locationId': location.locationId,
        'warehouseId': location.warehouseId,
        'aisle': location.aisle,
        'rack': location.rack,
        'shelf': location.shelf,
        'fullPath': location.getFullPath(),
        'capacity': location.capacity,
        'currentStock': location.getCurrentStock()
    } for location in locations]
    return render_template('LocationsPage.html', location_list=locations_data)

@app.route('/transactions')
def transactions():
    return render_template('TransactionsPage.html')

@app.route('/suppliers')
def suppliers():
    suppliers = Supplier.query.all()
    suppliers_data = [{
        'supplierId': supplier.supplierId,
        'name': supplier.name,
        'contact': supplier.contact,
        'address': supplier.address,
        'totalPurchases': supplier.get_total_purchases()
    } for supplier in suppliers]
    return render_template('SuppliersPage.html', suppliers=suppliers_data)

@app.route('/reports')
def reports():
    return render_template('ReportsPage.html')

@app.route('/users')
def users():
    users = User.query.all()
    users_data = [{
        'userId': user.userId,
        'username': user.username,
        'fullName': user.fullName,
        'role': user.role
    } for user in users]
    return render_template('UsersPage.html', users=users_data)

# New API routes for CRUD operations on items
@app.route('/api/items', methods=['GET'])
def get_items():
    items = ItemsList.query.all()
    return jsonify([{
        'sku': item.sku,
        'name': item.name,
        'description': item.description,
        'unit': item.unit,
        'totalStock': item.totalStock,
        'reorderPoint': item.reorderPoint,
        'supplierId': item.supplierId,  # Already string
        'status': 'In Stock' if item.totalStock > item.reorderPoint else 'Low Stock'
    } for item in items])

@app.route('/api/items', methods=['POST'])
def add_item():
    data = request.get_json()
    sku = ItemsList.get_next_sku()
    new_item = ItemsList(
        sku=sku,
        name=data['name'],
        description=data.get('description', ''),
        unit=data['unit'],
        reorderPoint=data['reorderPoint'],
        supplierId=data['supplierId'],  # String
        totalStock=data.get('totalStock', 0)
    )
    db.session.add(new_item)
    db.session.commit()
    return jsonify({'message': 'Item added successfully', 'sku': sku}), 201

@app.route('/api/items/<sku>', methods=['PUT'])
def update_item(sku):
    data = request.get_json()
    item = ItemsList.query.get_or_404(sku)
    item.name = data['name']
    item.description = data.get('description', '')
    item.unit = data['unit']
    item.reorderPoint = data['reorderPoint']
    item.supplierId = data['supplierId']  # String
    item.totalStock = data.get('totalStock', item.totalStock)
    db.session.commit()
    return jsonify({'message': 'Item updated successfully'})

@app.route('/api/items/<sku>', methods=['DELETE'])
def delete_item(sku):
    item = ItemsList.query.get_or_404(sku)
    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Item deleted successfully'})

# New API routes for CRUD operations on suppliers
@app.route('/api/suppliers', methods=['GET'])
def get_suppliers():
    suppliers = Supplier.query.all()
    return jsonify([{
        'supplierId': supplier.supplierId,  # String like SUP001
        'name': supplier.name,
        'contact': supplier.contact,
        'address': supplier.address,
        'totalPurchases': supplier.get_total_purchases()
    } for supplier in suppliers])

@app.route('/api/suppliers', methods=['POST'])
def add_supplier():
    data = request.get_json()
    supplier_id = data.get('supplierId')
    if not supplier_id:
        supplier_id = Supplier.get_next_id()
    if Supplier.query.get(supplier_id):
        return jsonify({'error': 'Supplier ID already exists'}), 400
    new_supplier = Supplier(
        supplierId=supplier_id,
        name=data['name'],
        contact=data['contact'],
        address=data['address']
    )
    db.session.add(new_supplier)
    db.session.commit()
    return jsonify({'message': 'Supplier added successfully'}), 201

@app.route('/api/suppliers/<supplierId>', methods=['PUT'])  # supplierId is string
def update_supplier(supplierId):
    data = request.get_json()
    supplier = Supplier.query.get_or_404(supplierId)
    supplier.name = data['name']
    supplier.contact = data['contact']
    supplier.address = data['address']
    db.session.commit()
    return jsonify({'message': 'Supplier updated successfully'})

@app.route('/api/suppliers/<supplierId>', methods=['DELETE'])  # supplierId is string
def delete_supplier(supplierId):
    supplier = Supplier.query.get_or_404(supplierId)
    db.session.delete(supplier)
    db.session.commit()
    return jsonify({'message': 'Supplier deleted successfully'})

# New API routes for CRUD operations on users
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify([{
        'userId': user.userId,
        'username': user.username,
        'fullName': user.fullName,
        'role': user.role.upper()  # Match HTML badge format
    } for user in users])

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    next_id = User.get_next_id()
    new_user = User(
        userId=next_id,
        username=data['username'],
        fullName=data['fullName'],
        password=data['password'],  # Plain-text; hash in production
        role=data['role']
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User added successfully', 'userId': next_id}), 201

@app.route('/api/users/<userId>', methods=['PUT'])
def update_user(userId):
    data = request.get_json()
    user = User.query.get_or_404(userId)
    # Check if username is being changed and if it's unique
    if data['username'] != user.username and User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    user.username = data['username']
    user.fullName = data['fullName']
    if 'password' in data and data['password']:  # Only update if provided
        user.password = data['password']
    user.role = data['role']
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route('/api/users/<userId>', methods=['DELETE'])
def delete_user(userId):
    user = User.query.get_or_404(userId)
    # Prevent deleting the current user (assume "admin" is current; use sessions for real check)
    if user.username == 'admin':
        return jsonify({'error': 'Cannot delete yourself'}), 400
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})

@app.route('/api/users/search', methods=['GET'])
def search_users():
    query = request.args.get('q', '').strip()
    if not query:
        return get_users()  # Return all if no query
    users = User.query.filter(
        or_(User.username.ilike(f'%{query}%'), User.fullName.ilike(f'%{query}%'))
    ).all()
    return jsonify([{
        'userId': user.userId,
        'username': user.username,
        'fullName': user.fullName,
        'role': user.role.upper()
    } for user in users])

@app.route('/api/items/search', methods=['GET'])
def search_items():
    query = request.args.get('q', '').strip()
    if not query:
        return get_items()  # Return all if no query
    items = ItemsList.query.filter(
        or_(ItemsList.sku.ilike(f'%{query}%'), ItemsList.name.ilike(f'%{query}%'))
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

# API routes for transactions
@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    transactions = Transaction.query.order_by(Transaction.date.desc()).all()
    return jsonify([{
        'transId': t.transId,
        'type': t.type,
        'date': t.date.isoformat(),
        'itemSku': t.itemSku,
        'quantity': t.quantity,
        'userId': t.userId,
        'notes': t.notes
    } for t in transactions])

@app.route('/api/transactions', methods=['POST'])
def create_transaction():
    data = request.get_json()
    trans_id = Transaction.get_next_trans_id()

    # Create transaction with single item
    transaction = Transaction(
        transId=trans_id,
        type=data['type'],
        userId=data['userId'],
        notes=data.get('notes', ''),
        supplierId=data.get('supplierId'),
        fromLocationId=data.get('fromLocationId'),
        toLocationId=data.get('toLocationId'),
        reason=data.get('reason'),
        itemSku=data['itemSku'],
        quantity=data['quantity'],
        locationId=data['locationId']
    )
    db.session.add(transaction)

    # Update item stock based on transaction type
    item_obj = ItemsList.query.get(data['itemSku'])
    if item_obj:
        if transaction.type == 'receive':
            item_obj.totalStock += data['quantity']
        elif transaction.type == 'issue':
            item_obj.totalStock -= data['quantity']
        elif transaction.type == 'adjustment':
            item_obj.totalStock += data['quantity']  # Can be negative

    db.session.commit()
    return jsonify({'message': 'Transaction created successfully', 'transId': trans_id}), 201

# API routes for locations
@app.route('/api/locations', methods=['GET'])
def get_locations():
    locations = Location.query.all()
    return jsonify([{
        'locationId': location.locationId,
        'warehouseId': location.warehouseId,
        'aisle': location.aisle,
        'rack': location.rack,
        'shelf': location.shelf,
        'fullPath': location.getFullPath(),
        'capacity': location.capacity,
        'currentStock': location.getCurrentStock()
    } for location in locations])

@app.route('/api/locations', methods=['POST'])
def add_location():
    data = request.get_json()
    location_id = Location.get_next_id()
    new_location = Location(
        locationId=location_id,
        warehouseId=data['warehouseId'],
        aisle=data['aisle'],
        rack=data['rack'],
        shelf=data['shelf'],
        capacity=data['capacity']
    )
    db.session.add(new_location)
    db.session.commit()
    return jsonify({'message': 'Location added successfully', 'locationId': location_id}), 201

@app.route('/api/locations/search', methods=['GET'])
def search_locations():
    query = request.args.get('q', '').strip()
    if not query:
        return get_locations()  # Return all if no query
    locations = Location.query.filter(
        or_(Location.locationId.ilike(f'%{query}%'), Location.warehouseId.ilike(f'%{query}%'))
    ).all()
    return jsonify([{
        'locationId': location.locationId,
        'warehouseId': location.warehouseId,
        'aisle': location.aisle,
        'rack': location.rack,
        'shelf': location.shelf,
        'fullPath': location.getFullPath(),
        'capacity': location.capacity,
        'currentStock': location.getCurrentStock()
    } for location in locations])

# Run the app and create tables if this file is executed directly
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Creates tables based on models
    app.run(debug=True)
