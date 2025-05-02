from flask import Flask, request, jsonify, g
from functools import wraps
import jwt
import datetime
import logging
import uuid
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # In production, use a secure environment variable

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Mock database for users
users_db = {
    'alice': {
        'username': 'alice',
        'password': generate_password_hash('password123'),
        'role': 'admin'
    },
    'bob': {
        'username': 'bob',
        'password': generate_password_hash('password456'),
        'role': 'user'
    }
}

# Mock resource database
resources_db = {
    '1': {'id': '1', 'name': 'Sensitive Document', 'owner': 'alice', 'content': 'Top secret information'},
    '2': {'id': '2', 'name': 'Public Document', 'owner': 'bob', 'content': 'Public information'}
}

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
            current_user = users_db.get(data['username'])
            
            if not current_user:
                logger.warning(f"Request {request_id}: User not found")
                return jsonify({'message': 'User not found'}), 401
            
            # Store user info in Flask's g object for this request
            g.current_user = current_user
            g.request_id = request_id
            
            logger.info(f"Request {request_id}: Authenticated as {current_user['username']}")
            
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
            if g.current_user['role'] != required_role and g.current_user['role'] != 'admin':
                logger.warning(f"Request {g.request_id}: Insufficient permissions for {g.current_user['username']}")
                return jsonify({'message': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Zero Trust Principle 3: Verify resource access - Resource ownership verification
def verify_resource_access(resource_id, action):
    resource = resources_db.get(resource_id)
    
    if not resource:
        logger.warning(f"Request {g.request_id}: Resource {resource_id} not found")
        return False, "Resource not found"
    
    # Admin can do anything
    if g.current_user['role'] == 'admin':
        return True, None
    
    # Owner can access their own resources
    if action == 'read' and (resource['owner'] == g.current_user['username'] or 'Public' in resource['name']):
        return True, None
    
    if action == 'write' and resource['owner'] == g.current_user['username']:
        return True, None
    
    logger.warning(f"Request {g.request_id}: Unauthorized access to resource {resource_id} by {g.current_user['username']}")
    return False, "Unauthorized access to resource"

# Routes
@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Authentication required'}), 401
    
    username = auth.get('username')
    user = users_db.get(username)
    
    if not user:
        return jsonify({'message': 'User not found'}), 401
    
    if check_password_hash(user['password'], auth.get('password')):
        # Generate JWT token
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        logger.info(f"User {username} logged in successfully")
        return jsonify({'token': token})
    
    logger.warning(f"Failed login attempt for user {username}")
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/resources', methods=['GET'])
@token_required
def get_all_resources():
    # Filter resources based on user's role
    if g.current_user['role'] == 'admin':
        result = list(resources_db.values())
    else:
        # Users can only see their own resources and public resources
        result = [r for r in resources_db.values() 
                 if r['owner'] == g.current_user['username'] or 'Public' in r['name']]
    
    logger.info(f"Request {g.request_id}: Returned {len(result)} resources to {g.current_user['username']}")
    return jsonify(result)

@app.route('/resources/<resource_id>', methods=['GET'])
@token_required
def get_resource(resource_id):
    # Verify access to the specific resource
    has_access, error_msg = verify_resource_access(resource_id, 'read')
    
    if not has_access:
        return jsonify({'message': error_msg}), 403
    
    logger.info(f"Request {g.request_id}: Resource {resource_id} accessed by {g.current_user['username']}")
    return jsonify(resources_db[resource_id])

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
    
    resources_db[resource_id]['content'] = data['content']
    logger.info(f"Request {g.request_id}: Resource {resource_id} updated by {g.current_user['username']}")
    return jsonify(resources_db[resource_id])

@app.route('/admin/users', methods=['GET'])
@token_required
@role_required('admin')
def get_all_users():
    # Only admins can access this endpoint due to @role_required decorator
    users = [{
        'username': user['username'],
        'role': user['role']
    } for user in users_db.values()]
    
    logger.info(f"Request {g.request_id}: All users accessed by admin {g.current_user['username']}")
    return jsonify(users)

# Health check endpoint - no authentication required
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    print("Zero Trust Flask Application running!")
    print("Available endpoints:")
    print("  POST /login - Get authentication token")
    print("  GET /resources - List accessible resources")
    print("  GET /resources/<id> - Get specific resource")
    print("  PUT /resources/<id> - Update specific resource")
    print("  GET /admin/users - Admin only: list all users")
    print("  GET /health - Health check")
    
    # In a real application, you would use HTTPS
    # app.run(ssl_context='adhoc')
    app.run(debug=True)