import requests
import json
import time
import os
import base64
import getpass

BASE_URL = 'http://localhost:5000'

def login(username, password, mfa_code=None):
    """Authenticate and get a JWT token"""
    payload = {'username': username, 'password': password}
    
    if mfa_code:
        payload['mfa_code'] = mfa_code
    
    response = requests.post(
        f'{BASE_URL}/login',
        json=payload
    )
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401 and response.json().get('mfa_required'):
        # MFA is required
        print("MFA code required for login.")
        mfa_code = input("Enter your MFA code: ")
        return login(username, password, mfa_code)
    else:
        print(f"Login failed: {response.json()['message']}")
        return None

def setup_mfa(token):
    """Set up MFA for the authenticated user"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.post(f'{BASE_URL}/mfa/setup', headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        secret = data['secret']
        qr_code = data['qr_code']
        
        # Save QR code to a file
        with open('mfa_qrcode.png', 'wb') as f:
            f.write(base64.b64decode(qr_code))
        
        print("\nMFA Setup Instructions:")
        print("1. Open your authenticator app (Google Authenticator, Authy, etc.)")
        print("2. Scan the QR code saved as 'mfa_qrcode.png' in the current directory")
        print(f"3. Or manually enter this secret key: {secret}")
        print("4. Enter the verification code from your app to enable MFA")
        
        code = input("Enter verification code: ")
        verify_mfa(token, code)
        return True
    else:
        print(f"Failed to set up MFA: {response.json()['message']}")
        return False

def verify_mfa(token, code):
    """Verify and enable MFA"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.post(
        f'{BASE_URL}/mfa/verify',
        headers=headers,
        json={'code': code}
    )
    
    if response.status_code == 200:
        print("MFA enabled successfully!")
        return True
    else:
        print(f"Failed to verify MFA: {response.json()['message']}")
        return False

def disable_mfa(token, code):
    """Disable MFA"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.post(
        f'{BASE_URL}/mfa/disable',
        headers=headers,
        json={'code': code}
    )
    
    if response.status_code == 200:
        print("MFA disabled successfully!")
        return True
    else:
        print(f"Failed to disable MFA: {response.json()['message']}")
        return False

def get_resources(token):
    """Get all resources accessible to the authenticated user"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{BASE_URL}/resources', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get resources: {response.json()['message']}")
        return None

def get_resource(token, resource_id):
    """Get a specific resource"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{BASE_URL}/resources/{resource_id}', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get resource: {response.json()['message']}")
        return None

def update_resource(token, resource_id, content):
    """Update a specific resource"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.put(
        f'{BASE_URL}/resources/{resource_id}',
        headers=headers,
        json={'content': content}
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to update resource: {response.json()['message']}")
        return None

def get_all_users(token):
    """Admin only: Get all users"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{BASE_URL}/admin/users', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get users: {response.json()['message']}")
        return None

def get_access_logs(token):
    """Admin only: Get access logs"""
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{BASE_URL}/admin/logs', headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get logs: {response.json()['message']}")
        return None

def mfa_demo():
    """Demo MFA setup and verification"""
    print("\n=== MFA Setup Demo ===")
    
    # Login as admin
    login_result = login('alice', 'password123')
    if not login_result:
        return
    
    token = login_result['token']
    
    # Set up MFA
    print("\nSetting up MFA for admin user...")
    setup_mfa(token)
    
    # Test login with MFA
    print("\nTesting login with MFA...")
    print("You will be prompted for your MFA code")
    login_result = login('alice', 'password123')
    
    if login_result:
        print("✅ Login with MFA successful")
        
        # Disable MFA at the end of the demo
        print("\nDisabling MFA...")
        code = input("Enter your MFA code to disable MFA: ")
        disable_mfa(login_result['token'], code)

def demo():
    # Scenario 1: Admin user login and access
    print("\n=== Admin User (Alice) ===")
    login_result = login('alice', 'password123')
    if login_result:
        admin_token = login_result['token']
        print("✅ Admin login successful")
        
        # Get all resources (admin can see all)
        resources = get_resources(admin_token)
        if resources:
            print(f"✅ Admin can see {len(resources)} resources:")
            for r in resources:
                print(f"  - {r['name']} (owned by {r['owner']})")
        
        # Admin can access any resource
        resource = get_resource(admin_token, '2')
        if resource:
            print(f"✅ Admin can access resource: {resource['name']}")
        
        # Admin can update any resource
        updated = update_resource(admin_token, '2', 'Updated by admin')
        if updated:
            print(f"✅ Admin updated resource: {updated['name']}")
        
        # Admin can see all users
        users = get_all_users(admin_token)
        if users:
            print(f"✅ Admin can see all users:")
            for user in users:
                
    
    
                print(f"  - {user['username']} (role: {user['role']})")
        
        # Admin can view access logs
        logs = get_access_logs(admin_token)
        if logs:
            print(f"✅ Admin can view access logs (showing last 3):")
            for log in logs[:3]:
                print(f"  - {log['timestamp']}: {log['action']} by {log['user']} - {'Success' if log['success'] else 'Failed'}")
    
    # Scenario 2: Regular user login and access
    print("\n=== Regular User (Bob) ===")
    login_result = login('bob', 'password456')
    if login_result:
        user_token = login_result['token']
        print("✅ User login successful")
        
        # Get accessible resources (only own and public)
        resources = get_resources(user_token)
        if resources:
            print(f"✅ User can see {len(resources)} resources:")
            for r in resources:
                print(f"  - {r['name']} (owned by {r['owner']})")
        
        # User can access their own resource
        resource = get_resource(user_token, '2')
        if resource:
            print(f"✅ User can access their own resource: {resource['name']}")
        
        # User cannot access admin's resource
        resource = get_resource(user_token, '1')
        if not resource:
            print(f"✅ User cannot access admin's resource")
        
        # User can update their own resource
        updated = update_resource(user_token, '2', 'Updated by user')
        if updated:
            print(f"✅ User updated their own resource: {updated['name']}")
        
        # User cannot update admin's resource
        updated = update_resource(user_token, '1', 'Attempt to update admin resource')
        if not updated:
            print(f"✅ User cannot update admin's resource")
        
        # User cannot access admin endpoints
        users = get_all_users(user_token)
        if not users:
            print(f"✅ User cannot access admin endpoints")
        
        # User cannot access logs
        logs = get_access_logs(user_token)
        if not logs:
            print(f"✅ User cannot access access logs")
    
    # Scenario 3: Invalid credentials
    print("\n=== Invalid Login ===")
    invalid_token = login('mallory', 'hackpassword')
    if not invalid_token:
        print("✅ Invalid login rejected")

if __name__ == "__main__":
    print("Zero Trust API Client Demo")
    print("=========================")
    
    while True:
        print("\nSelect an option:")
        print("1. Run standard demo (test basic functionality)")
        print("2. Set up and test MFA")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == '1':
            demo()
        elif choice == '2':
            mfa_demo()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")