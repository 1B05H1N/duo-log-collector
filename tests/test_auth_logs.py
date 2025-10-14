#!/usr/bin/env python3
"""
Test Duo Authentication Logs Collection

This script tests the connection to Duo's Admin API specifically for
authentication log collection and verifies that credentials and permissions
are working correctly.

Usage:
    python test_auth_logs.py
"""

import os
import sys
from datetime import datetime, timedelta
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from duo_auth_logs_only import DuoAuthLogCollector, load_credentials


def test_auth_log_connection():
    """Test authentication log collection specifically"""
    print("Testing Duo Authentication Log Collection")
    print("=" * 50)
    
    try:
        # Load credentials
        print("1. Loading credentials...")
        integration_key, secret_key, api_hostname = load_credentials()
        print(f"   Integration Key: {integration_key[:8]}...")
        print(f"   API Hostname: {api_hostname}")
        print("   [OK] Credentials loaded successfully")
        
        # Initialize collector
        print("\n2. Initializing authentication log collector...")
        collector = DuoAuthLogCollector(integration_key, secret_key, api_hostname)
        print("   [OK] Collector initialized")
        
        # Test authentication log access
        print("\n3. Testing authentication log access...")
        try:
            # Try to get a small sample of authentication logs (last 24 hours)
            end_time = int(datetime.now().timestamp())
            start_time = int((datetime.now() - timedelta(hours=24)).timestamp())
            
            logs, next_offset = collector.get_authentication_logs(
                mintime=start_time,
                maxtime=end_time,
                limit=5  # Just get a few logs for testing
            )
            
            print(f"   [OK] Authentication log access: OK")
            print(f"   [OK] Retrieved {len(logs)} sample authentication logs")
            
            if logs:
                print(f"\n4. Sample Authentication Log Analysis:")
                print(f"   Time range: {datetime.fromtimestamp(start_time)} to {datetime.fromtimestamp(end_time)}")
                
                # Analyze the sample logs
                results = {}
                factors = {}
                users = set()
                
                for log in logs:
                    result = log.get('result', 'UNKNOWN')
                    results[result] = results.get(result, 0) + 1
                    
                    factor = log.get('factor', 'UNKNOWN')
                    factors[factor] = factors.get(factor, 0) + 1
                    
                    if log.get('username'):
                        users.add(log['username'])
                
                print(f"   Authentication results: {results}")
                print(f"   Authentication factors: {factors}")
                print(f"   Unique users in sample: {len(users)}")
                
                # Show sample log structure
                if logs:
                    sample_log = logs[0]
                    print(f"\n5. Sample Log Entry Structure:")
                    for key, value in sample_log.items():
                        if key == 'timestamp' and value:
                            readable_time = datetime.fromtimestamp(value).isoformat()
                            print(f"   {key}: {readable_time}")
                        else:
                            print(f"   {key}: {value}")
            else:
                print("   Note: No authentication logs found in the last 24 hours")
                print("   This may be normal if there has been no recent activity")
        
        except Exception as e:
            print(f"   [ERROR] Authentication log access failed: {str(e)}")
            print("   Note: This may indicate missing 'Grant read log' permission")
            return False
        
        print("\n" + "=" * 50)
        print("[OK] Authentication log collection test completed successfully!")
        print("You can now run the main authentication log collector script.")
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        print("\nTroubleshooting tips:")
        print("1. Verify your Duo API credentials are correct")
        print("2. Check that your Admin API application is active")
        print("3. Ensure you have 'Grant read log' permission")
        print("4. Verify network connectivity to Duo's API endpoints")
        print("5. Check for IP restrictions in Duo Admin Panel")
        return False


def main():
    """Main function"""
    success = test_auth_log_connection()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
