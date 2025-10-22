#!/usr/bin/env python3
"""
Test script for ALL Threat Intelligence APIs
"""

import asyncio
import json
import logging
from analyzers.threat_intel import ThreatIntelligence

logging.basicConfig(level=logging.INFO)

async def test_all_apis():
    """Test all threat intelligence API integrations."""

    # Load your API keys from config
    try:
        with open('config/api_keys.json') as f:
            api_keys = json.load(f)
    except FileNotFoundError:
        print("❌ Error: config/api_keys.json not found!")
        return
    except json.JSONDecodeError:
        print("❌ Error: Invalid JSON in config/api_keys.json")
        return

    # Configuration
    config = {
        'api_keys': api_keys,
        'timeouts': {'threat_intel': 60}
    }

    domain = "linkedin.com"

    print("=" * 70)
    print("🔍 Complete Threat Intelligence Analysis")
    print("=" * 70)
    print(f"\n📍 Target Domain: {domain}")
    print("⏳ Analyzing with multiple threat intel sources...\n")

    # Initialize Threat Intelligence module
    threat_intel = ThreatIntelligence(config)

    # Run the analysis (runs all APIs in parallel)
    result = await threat_intel.analyze_domain(domain)

    print("=" * 70)
    print("📊 ANALYSIS RESULTS")
    print("=" * 70)

    # VirusTotal Results
    print("\n🦠 VirusTotal Analysis")
    print("-" * 70)
    vt_result = result.get('virustotal', {})
    if vt_result.get('available'):
        print("✅ VirusTotal: Available")
        stats = result.get('last_analysis_stats', {})
        print(f"   Malicious: {stats.get('malicious', 0)}")
        print(f"   Suspicious: {stats.get('suspicious', 0)}")
        print(f"   Clean: {stats.get('harmless', 0)}")
        print(f"   Reputation: {result.get('reputation', 'N/A')}")
    elif vt_result.get('error'):
        print(f"⚠️  VirusTotal: {vt_result.get('error')}")
    else:
        print("❌ VirusTotal: Not configured")

    # Netlas Results
    print("\n🌐 Netlas Analysis")
    print("-" * 70)
    netlas_result = result.get('netlas', {})
    if netlas_result.get('available'):
        print("✅ Netlas: Available")
        data = netlas_result.get('data', {})
        if isinstance(data, dict):
            print(f"   Domain: {data.get('domain', 'N/A')}")
            print(f"   IPs Found: {len(data.get('ips', []))}")
    elif netlas_result.get('error'):
        print(f"⚠️  Netlas: {netlas_result.get('error')}")
    else:
        print("❌ Netlas: Not configured")

    # Censys Results
    print("\n🔍 Censys Analysis")
    print("-" * 70)
    censys_result = result.get('censys', {})
    if censys_result.get('available'):
        print("✅ Censys: Available")
        print(f"   Hosts Found: {len(censys_result.get('data', []))}")
        for i, host in enumerate(censys_result.get('data', [])[:3], 1):  # Show first 3
            print(f"\n   Host #{i}:")
            print(f"      IP: {host.get('ip', 'N/A')}")
            if 'location' in host:
                loc = host['location']
                print(f"      Location: {loc.get('city', 'N/A')}, {loc.get('country', 'N/A')}")
    elif censys_result.get('error'):
        print(f"⚠️  Censys: {censys_result.get('error')}")
    else:
        print("❌ Censys: Not configured")

    # Overall Assessment
    print("\n" + "=" * 70)
    print("📈 Overall Threat Assessment")
    print("=" * 70)
    print(f"Threat Score: {result.get('threat_score', 0)}/100")
    print(f"Is Malicious: {'YES ⚠️' if result.get('is_malicious') else 'NO ✅'}")

    print("\n" + "=" * 70)
    print("✨ Analysis Complete!")
    print("=" * 70)

if __name__ == "__main__":
    try:
        asyncio.run(test_all_apis())
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
