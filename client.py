import requests
import json

BASE_URL = 'http://localhost:5000'

def login(username, password):
    """Authenticate and get a JWT token"""
    response = requests.post(
        f'{BASE_URL}/login',
        json={'username': username, 'password': password}
    )
    
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(f"Login failed: {response.json()['message']}")
        return None

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

def demo():
    # Scenario 1: Admin user login and access
    print("\n=== Admin User (Alice) ===")
    admin_token = login('alice', 'password123')
    if admin_token:
        print("✅ Admin login successful")
        
        # Get all resources (admin can see all)
        resources = get_resources(admin_token)
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
    
    # Scenario 2: Regular user login and access
    print("\n=== Regular User (Bob) ===")
    user_token = login('bob', 'password456')
    if user_token:
        print("✅ User login successful")
        
        # Get accessible resources (only own and public)
        resources = get_resources(user_token)
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
    
    # Scenario 3: Invalid credentials
    print("\n=== Invalid Login ===")
    invalid_token = login('mallory', 'hackpassword')
    if not invalid_token:
        print("✅ Invalid login rejected")

if __name__ == "__main__":
    print("Zero Trust API Client Demo")
    print("=========================")
    demo()