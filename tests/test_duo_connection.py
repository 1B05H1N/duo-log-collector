#!/usr/bin/env python3
"""
Duo API Connection Test Script

This script tests the connection to Duo's Admin API and verifies
that credentials are working correctly. Use this to troubleshoot
authentication issues before running the main log collector.

Usage:
    python test_duo_connection.py
"""

import os
import sys
import json
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from duo_log_collector import DuoAPIClient, load_credentials


def test_api_connection():
    """Test basic API connection and authentication"""
    print("Testing Duo Admin API Connection")
    print("=" * 40)
    
    try:
        # Load credentials
        print("1. Loading credentials...")
        integration_key, secret_key, api_hostname = load_credentials()
        print(f"   Integration Key: {integration_key[:8]}...")
        print(f"   API Hostname: {api_hostname}")
        print("   ✓ Credentials loaded successfully")
        
        # Initialize client
        print("\n2. Initializing API client...")
        client = DuoAPIClient(integration_key, secret_key, api_hostname)
        print("   ✓ Client initialized")
        
        # Test basic API call (get account info)
        print("\n3. Testing API authentication...")
        try:
            response = client._make_request('GET', '/admin/v1/info/summary')
            if response.get('stat') == 'OK':
                print("   ✓ Authentication successful")
                
                # Display account info
                account_info = response.get('response', {})
                print(f"\n4. Account Information:")
                print(f"   Edition: {account_info.get('edition', 'Unknown')}")
                print(f"   User Count: {account_info.get('user_count', 'Unknown')}")
                print(f"   Admin Count: {account_info.get('admin_count', 'Unknown')}")
                print(f"   Integration Count: {account_info.get('integration_count', 'Unknown')}")
                
            else:
                print(f"   ✗ Authentication failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            print(f"   ✗ API call failed: {str(e)}")
            return False
        
        # Test log access permissions
        print("\n5. Testing log access permissions...")
        try:
            # Try to get a small sample of authentication logs
            logs = client.get_authentication_logs(limit=1)
            print("   ✓ Authentication log access: OK")
        except Exception as e:
            print(f"   ✗ Authentication log access failed: {str(e)}")
            print("   Note: This may indicate missing 'Grant read log' permission")
        
        try:
            # Try to get a small sample of admin logs
            logs = client.get_administrator_logs(limit=1)
            print("   ✓ Administrator log access: OK")
        except Exception as e:
            print(f"   ✗ Administrator log access failed: {str(e)}")
            print("   Note: This may indicate missing 'Grant read log' permission")
        
        print("\n" + "=" * 40)
        print("✓ Connection test completed successfully!")
        print("You can now run the main log collector script.")
        return True
        
    except Exception as e:
        print(f"\n✗ Connection test failed: {str(e)}")
        print("\nTroubleshooting tips:")
        print("1. Verify your Duo API credentials are correct")
        print("2. Check that your Admin API application is active")
        print("3. Ensure you have 'Grant read log' permission")
        print("4. Verify network connectivity to Duo's API endpoints")
        print("5. Check for IP restrictions in Duo Admin Panel")
        return False


def main():
    """Main function"""
    success = test_api_connection()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
