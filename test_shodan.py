#!/usr/bin/env python3
"""
Shodan API Test Script

Test Shodan IP and domain lookups.

Owner: Samyama.ai - Vaidhyamegha Private Limited
Version: 1.0.0
"""

import asyncio
import json
import sys
from analyzers.threat_intel import ThreatIntelligence

async def test_shodan():
    """Test Shodan API integration."""
    
    # Load your API key from config
    try:
        with open('config/api_keys.json') as f:
            api_keys = json.load(f)
    except FileNotFoundError:
        print("❌ Error: config/api_keys.json not found!")
        print("Please create the file with your Shodan API key.")
        return
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON in config/api_keys.json")
        print("Please check the file syntax.")
        return
    
    # Configuration
    config = {
        'api_keys': api_keys,
        'timeouts': {'threat_intel': 60}
    }
    
    # Get target from command line or use default
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "8.8.8.8"  # Default to Google DNS
    
    print("=" * 70)
    print("🔍 Shodan Analysis")
    print("=" * 70)
    print(f"\n🎯 Target: {target}")
    print("⏳ Analyzing...\n")
    
    # Initialize threat intelligence
    ti = ThreatIntelligence(config)
    
    try:
        # Check if it's an IP or domain
        if target.replace('.', '').isdigit():
            result = await ti.analyze_ip(target)
        else:
            result = await ti.analyze_domain(target)
        
        # Print results
        print("✅ Analysis Complete!\n")
        print(json.dumps(result, indent=2, default=str))
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        if "Invalid API key" in str(e):
            print("\nℹ️  Make sure your Shodan API key is valid and has the required permissions.")
    
    print("\n" + "=" * 70)
    print("🏁 Test Complete")
    print("=" * 70)

if __name__ == "__main__":
    try:
        asyncio.run(test_shodan())
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
