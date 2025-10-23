#!/usr/bin/env python3
"""
Test script for Censys Platform API v3 integration.
Tests domain search functionality using the new SDK.

Usage:
    python test_censys.py [domain]
    
If no domain is provided, defaults to 'example.com'
"""

import asyncio
import json
import logging
import sys
from analyzers.threat_intel import ThreatIntelligence

logging.basicConfig(level=logging.INFO)

async def test_censys():
    """Test Censys API integration."""
    
    # Load your API key from config
    try:
        with open('config/api_keys.json') as f:
            api_keys = json.load(f)
    except FileNotFoundError:
        print("❌ Error: config/api_keys.json not found!")
        print("Please create the file with your Censys API credentials.")
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
    
    # Get domain from command line argument or use default
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    
    print("=" * 70)
    print("🔍 Censys Domain Analysis")
    print("=" * 70)
    print(f"\n📍 Target Domain: {domain}")
    print("⏳ Analyzing... (This may take 5-10 seconds)\n")
    
    # Initialize Threat Intelligence module
    threat_intel = ThreatIntelligence(config)
    
    # Run the analysis
    result = await threat_intel.analyze_domain(domain)
    
    # Display Results
    print("=" * 70)
    print("📊 ANALYSIS RESULTS")
    print("=" * 70)
    
    censys_result = result.get('censys', {})
    if censys_result.get('available'):
        print("\n🛡️  Censys Analysis Details")
        print("=" * 70)
        print(f"✅ Found {len(censys_result.get('data', []))} hosts")
        print("\nHost Details:")
        for i, host in enumerate(censys_result.get('data', []), 1):
            print(f"\n  Host #{i}:")
            print(f"    IP: {host.get('ip', 'N/A')}")
            if 'location' in host:
                loc = host['location']
                print(f"    Location: {loc.get('city', 'N/A')}, {loc.get('country', 'N/A')}")
            if 'autonomous_system' in host:
                asn = host['autonomous_system']
                print(f"    ASN: {asn.get('asn', 'N/A')} - {asn.get('name', 'N/A')}")
            if 'services' in host:
                print(f"    Services: {len(host['services'])} detected")
        
        print("\n\n📄 Full JSON Response:")
        print("=" * 70)
        print(json.dumps(censys_result.get('data', []), indent=2))
    elif censys_result.get('error'):
        print(f"\n❌ Censys Error: {censys_result.get('error')}")
    else:
        print("\n❌ Censys Error: Unknown error or no data returned.")

    print("\n" + "=" * 70)
    print("✨ Analysis Complete!")
    print("=" * 70)

if __name__ == "__main__":
    try:
        asyncio.run(test_censys())
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
