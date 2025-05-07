from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
import datetime
import logging
import uuid
import os
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Resource, AccessLog

# Create Flask app
app = Flask(__name__, instance_relative_config=True)

# Configure app
app.config['SECRET_KEY'] = 'your-secret-key'  # In production, use a secure environment variable

# Set the correct database path to use the instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'zero_trust.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Ensure the instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

# Initialize the database with the app
db.init_app(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Function to initialize the database
def init_db():
    # Create tables if they don't exist
    db.create_all()
    
    # Check if we need to create initial data
    if User.query.count() == 0:
        print("Creating initial data...")
        # Create admin user
        admin = User(username='alice', role='admin')
        admin.set_password('password123')
        
        # Create regular user
        user = User(username='bob', role='user')
        user.set_password('password456')
        
        # Add users to database
        db.session.add(admin)
        db.session.add(user)
        db.session.commit()
        
        # Create resources
        resource1 = Resource(
            name='Sensitive Document',
            content='Top secret information',
            owner_id=admin.id,
            is_public=False
        )
        
        resource2 = Resource(
            name='Public Document',
            content='Public information',
            owner_id=user.id,
            is_public=True
        )
        
        # Add resources to database
        db.session.add(resource1)
        db.session.add(resource2)
        db.session.commit()
        
        logger.info("Initial data created")
    else:
        print("Database already contains data, skipping initialization")

# Zero Trust Principle 1: Verify explicitly - Authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        request_id = str(uuid.uuid4())
        
        # Log every request
        logger.info(f"Request {request_id}: {request.method} {request.path} from {request.remote_addr}")
        
        # Extract token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            logger.warning(f"Request {request_id}: No token provided")
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Decode and verify token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
            
            if not current_user:
                logger.warning(f"Request {request_id}: User not found")
                return jsonify({'message': 'User not found'}), 401
            
            # Store user info in Flask's g object for this request
            g.current_user = current_user
            g.request_id = request_id
            
            logger.info(f"Request {request_id}: Authenticated as {current_user.username}")
            
        except jwt.ExpiredSignatureError:
            logger.warning(f"Request {request_id}: Token expired")
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            logger.warning(f"Request {request_id}: Invalid token")
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

# Zero Trust Principle 2: Use least privilege access - Role-based authorization
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if g.current_user.role != required_role and g.current_user.role != 'admin':
                logger.warning(f"Request {g.request_id}: Insufficient permissions for {g.current_user.username}")
                
                # Log the access attempt
                log_entry = AccessLog(
                    request_id=g.request_id,
                    action='admin_access',
                    success=False,
                    user_id=g.current_user.id,
                    ip_address=request.remote_addr
                )
                db.session.add(log_entry)
                db.session.commit()
                
                return jsonify({'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Zero Trust Principle 3: Verify resource access - Resource ownership verification
def verify_resource_access(resource_id, action):
    resource = Resource.query.get(resource_id)
    
    if not resource:
        logger.warning(f"Request {g.request_id}: Resource {resource_id} not found")
        return False, "Resource not found"
    
    # Admin can do anything
    if g.current_user.role == 'admin':
        # Log successful access
        log_entry = AccessLog(
            request_id=g.request_id,
            action=action,
            success=True,
            user_id=g.current_user.id,
            resource_id=resource.id,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        return True, None
    
    # Owner can access their own resources
    if action == 'read' and (resource.owner_id == g.current_user.id or resource.is_public):
        # Log successful access
        log_entry = AccessLog(
            request_id=g.request_id,
            action=action,
            success=True,
            user_id=g.current_user.id,
            resource_id=resource.id,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        return True, None
    
    if action == 'write' and resource.owner_id == g.current_user.id:
        # Log successful access
        log_entry = AccessLog(
            request_id=g.request_id,
            action=action,
            success=True,
            user_id=g.current_user.id,
            resource_id=resource.id,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        return True, None
    
    # Log failed access attempt
    log_entry = AccessLog(
        request_id=g.request_id,
        action=action,
        success=False,
        user_id=g.current_user.id,
        resource_id=resource.id,
        ip_address=request.remote_addr
    )
    db.session.add(log_entry)
    db.session.commit()
    
    logger.warning(f"Request {g.request_id}: Unauthorized access to resource {resource_id} by {g.current_user.username}")
    return False, "Unauthorized access to resource"

# Routes
@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    request_id = str(uuid.uuid4())
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Authentication required'}), 401
    
    username = auth.get('username')
    user = User.query.filter_by(username=username).first()
    
    # Log the login attempt
    log_entry = AccessLog(
        request_id=request_id,
        action='login',
        success=False,  # Default to failed, will update if successful
        ip_address=request.remote_addr
    )
    
    if not user:
        logger.warning(f"Login attempt for non-existent user: {username}")
        db.session.add(log_entry)
        db.session.commit()
        return jsonify({'message': 'User not found'}), 401
    
    log_entry.user_id = user.id
    
    if user.check_password(auth.get('password')):
        # Check if MFA is enabled for this user
        if user.mfa_enabled:
            # If MFA is enabled, we need a verification code
            if not auth.get('mfa_code'):
                db.session.add(log_entry)
                db.session.commit()
                return jsonify({
                    'message': 'MFA code required',
                    'mfa_required': True
                }), 401
            
            # Verify the MFA code
            if not user.verify_totp(auth.get('mfa_code')):
                logger.warning(f"Invalid MFA code for user {username}")
                db.session.add(log_entry)
                db.session.commit()
                return jsonify({'message': 'Invalid MFA code'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        # Update log entry to success
        log_entry.success = True
        db.session.add(log_entry)
        db.session.commit()
        
        logger.info(f"User {username} logged in successfully")
        return jsonify({
            'token': token,
            'mfa_enabled': user.mfa_enabled
        })
    
    # Password check failed
    db.session.add(log_entry)
    db.session.commit()
    logger.warning(f"Failed login attempt for user {username}")
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/mfa/setup', methods=['POST'])
@token_required
def setup_mfa():
    """Set up MFA for the authenticated user"""
    user = g.current_user
    
    # Generate a new MFA secret
    secret = user.generate_mfa_secret()
    
    # Generate a QR code for easy setup
    totp_uri = user.get_totp_uri()
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert the image to a base64 string
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Save the secret but don't enable MFA yet
    db.session.commit()
    
    return jsonify({
        'secret': secret,
        'qr_code': img_str
    })

@app.route('/mfa/verify', methods=['POST'])
@token_required
def verify_mfa():
    """Verify and enable MFA for the authenticated user"""
    user = g.current_user
    data = request.json
    
    if not data or not data.get('code'):
        return jsonify({'message': 'Verification code required'}), 400
    
    # Create a TOTP object
    totp = pyotp.TOTP(user.mfa_secret)
    
    # Verify the code
    if totp.verify(data.get('code')):
        # Enable MFA for the user
        user.mfa_enabled = True
        db.session.commit()
        
        logger.info(f"MFA enabled for user {user.username}")
        return jsonify({'message': 'MFA enabled successfully'})
    else:
        logger.warning(f"Invalid MFA verification code for user {user.username}")
        return jsonify({'message': 'Invalid verification code'}), 400

@app.route('/mfa/disable', methods=['POST'])
@token_required
def disable_mfa():
    """Disable MFA for the authenticated user"""
    user = g.current_user
    data = request.json
    
    if not data or not data.get('code'):
        return jsonify({'message': 'Verification code required'}), 400
    
    # Verify the code before disabling MFA
    if user.verify_totp(data.get('code')):
        # Disable MFA
        user.mfa_enabled = False
        user.mfa_secret = None
        db.session.commit()
        
        logger.info(f"MFA disabled for user {user.username}")
        return jsonify({'message': 'MFA disabled successfully'})
    else:
        logger.warning(f"Invalid MFA code when attempting to disable MFA for user {user.username}")
        return jsonify({'message': 'Invalid verification code'}), 400

@app.route('/resources', methods=['GET'])
@token_required
def get_all_resources():
    # Filter resources based on user's role
    if g.current_user.role == 'admin':
        resources = Resource.query.all()
    else:
        # Users can only see their own resources and public resources
        resources = Resource.query.filter(
            (Resource.owner_id == g.current_user.id) | (Resource.is_public == True)
        ).all()
    
    # Log the access
    log_entry = AccessLog(
        request_id=g.request_id,
        action='list_resources',
        success=True,
        user_id=g.current_user.id,
        ip_address=request.remote_addr
    )
    db.session.add(log_entry)
    db.session.commit()
    
    result = [resource.to_dict() for resource in resources]
    logger.info(f"Request {g.request_id}: Returned {len(result)} resources to {g.current_user.username}")
    return jsonify(result)

@app.route('/resources/<resource_id>', methods=['GET'])
@token_required
def get_resource(resource_id):
    # Verify access to the specific resource
    has_access, error_msg = verify_resource_access(resource_id, 'read')
    
    if not has_access:
        return jsonify({'message': error_msg}), 403
    
    resource = Resource.query.get(resource_id)
    logger.info(f"Request {g.request_id}: Resource {resource_id} accessed by {g.current_user.username}")
    return jsonify(resource.to_dict())

@app.route('/resources/<resource_id>', methods=['PUT'])
@token_required
def update_resource(resource_id):
    # Verify access to the specific resource
    has_access, error_msg = verify_resource_access(resource_id, 'write')
    
    if not has_access:
        return jsonify({'message': error_msg}), 403
    
    data = request.json
    if not data or not data.get('content'):
        return jsonify({'message': 'Invalid request data'}), 400
    
    resource = Resource.query.get(resource_id)
    resource.content = data['content']
    resource.updated_at = datetime.datetime.utcnow()
    db.session.commit()
    
    logger.info(f"Request {g.request_id}: Resource {resource_id} updated by {g.current_user.username}")
    return jsonify(resource.to_dict())

@app.route('/admin/users', methods=['GET'])
@token_required
@role_required('admin')
def get_all_users():
    # Only admins can access this endpoint due to @role_required decorator
    users = User.query.all()
    result = [user.to_dict() for user in users]
    
    logger.info(f"Request {g.request_id}: All users accessed by admin {g.current_user.username}")
    return jsonify(result)

@app.route('/admin/logs', methods=['GET'])
@token_required
@role_required('admin')
def get_access_logs():
    # Only admins can access logs
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(100).all()
    result = [log.to_dict() for log in logs]
    
    logger.info(f"Request {g.request_id}: Access logs viewed by admin {g.current_user.username}")
    return jsonify(result)

# Health check endpoint - no authentication required
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize the database before running the app
    
    print("Zero Trust Flask Application running!")
    print("Available endpoints:")
    print("  POST /login - Get authentication token")
    print("  POST /mfa/setup - Set up MFA for authenticated user")
    print("  POST /mfa/verify - Verify and enable MFA")
    print("  POST /mfa/disable - Disable MFA")
    print("  GET /resources - List accessible resources")
    print("  GET /resources/<id> - Get specific resource")
    print("  PUT /resources/<id> - Update specific resource")
    print("  GET /admin/users - Admin only: list all users")
    print("  GET /admin/logs - Admin only: view access logs")
    print("  GET /health - Health check")
    
    # In a real application, you would use HTTPS
    # app.run(ssl_context='adhoc')
    app.run(debug=True)