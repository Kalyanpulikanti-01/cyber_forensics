# Shodan.io Integration

## Why We Use It

Shodan.io is the world's first search engine for internet-connected devices, often called the "Google for hackers." It provides comprehensive visibility into exposed services, vulnerabilities, and infrastructure details. In our cyber forensics toolkit, Shodan helps identify security weaknesses, enumerate open services, and discover potential attack vectors on target systems.

## What We Get

Shodan provides extensive intelligence about internet-facing assets:

- **Host Information**: Detailed data about IP addresses including organization, ISP, and geolocation.
- **Open Ports & Services**: Complete enumeration of running services with version information.
- **Vulnerabilities**: Known CVEs and security issues detected on the target host.
- **SSL/TLS Certificates**: Certificate details, validity, and chain information.
- **Hostnames & DNS**: All associated domain names and DNS records.
- **Historical Data**: Track changes in infrastructure over time.
- **Banners & Headers**: Raw service banners revealing software versions and configurations.
- **Technology Stack**: Identification of web servers, frameworks, and technologies in use.

## How It Helps the Project

Shodan strengthens our forensic analysis and threat intelligence capabilities by:

- **Vulnerability Discovery**: Automatically identify known security vulnerabilities (CVEs) on target IPs.
- **Service Enumeration**: Map all exposed services to understand the attack surface.
- **Infrastructure Attribution**: Discover hosting providers, geographical location, and related infrastructure.
- **Evidence Collection**: Gather detailed technical data for comprehensive forensic reports.
- **Threat Assessment**: Enhance risk scoring with vulnerability and exposure data.
- **Related Host Discovery**: Find other systems in the same network or organization.

## Plans and Pricing

We currently use the **Freelancer/Membership** plan.

### Membership Plan (Paid - $59/month)

- **API Queries**: 100 query credits per month.
- **Scan Credits**: 5,120 monthly scan credits.
- **Host Lookups**: Unlimited IP/host information lookups (using `host()` method).
- **Features**: Full access to vulnerability data, historical data, and all API endpoints.
- **Commercial Use**: Allowed for business and commercial applications.

### Free/Developer Plan (Limited)

- **API Queries**: Very limited (1 query credit).
- **Host Lookups**: Limited free lookups per month.
- **Features**: Basic host information only, no search capabilities.
- **Limitations**: Sufficient for testing but not production use.

### Enterprise Plan (Custom Pricing)

- **Unlimited Access**: No monthly limits on queries or scans.
- **Advanced Features**: Priority support, custom integrations, bulk data access.
- **Cost**: Custom pricing based on organization size and usage requirements.

For this project, the **Membership plan** ($59/month) provides excellent value with adequate query credits for regular forensic investigations while maintaining access to critical vulnerability and historical data.

## Current Implementation

Our Shodan integration is implemented directly in the `ThreatIntelligence` class (`analyzers/threat_intel.py`):

### Features Implemented

1. **IP Address Analysis** (`_check_shodan_ip()`):
   - Retrieves complete host information for any public IP
   - Includes ports, services, vulnerabilities, and metadata
   - Automatically skips private IP addresses

2. **Domain Search** (`_check_shodan_domain()`):
   - Searches for all hosts associated with a domain
   - Uses hostname-based queries
   - Returns comprehensive infrastructure mapping

3. **Integration Points**:
   - `analyze_ip()`: Includes Shodan data in IP reputation analysis
   - `analyze_domain()`: Adds Shodan results to domain intelligence
   - Vulnerability data automatically extracted and counted

### Key Benefits

- **Async Implementation**: Non-blocking API calls using `asyncio.run_in_executor()`
- **Error Handling**: Graceful degradation if API is unavailable or rate-limited
- **Free Tier Compatible**: Works with free plan for IP lookups
- **Smart Detection**: Only queries public IPs (skips private/internal addresses)

## Configuration

In `config/api_keys.json`:

```json
{
  "shodan": "your_shodan_api_key_here"
}
```

Get your API key from: https://account.shodan.io/

## Testing the Integration

Test the Shodan integration with the included test script:

```bash
# Activate virtual environment
source venv/bin/activate

# Test IP analysis
python test_shodan.py 8.8.8.8

# Test domain analysis
python test_shodan.py google.com
```

Expected output includes:
- Organization and ISP information
- Geolocation (city, country, coordinates)
- Open ports and running services
- SSL/TLS certificate details
- DNS information and hostnames
- Detected vulnerabilities (if any)

## API Methods Used

### 1. `host(ip)` - IP Lookup
```python
result = shodan_client.host('8.8.8.8')
```
Returns complete information about a specific IP address.

**Free Tier**: ✅ Limited lookups available
**Paid Tier**: ✅ Unlimited

### 2. `search(query)` - Advanced Search
```python
result = shodan_client.search('hostname:example.com')
```
Searches Shodan database for matching hosts.

**Free Tier**: ❌ Not available
**Paid Tier**: ✅ Available (uses query credits)

## Integration in Analysis Pipeline

Shodan data is automatically included when analyzing:

1. **IP Addresses**:
   - Public IPs get full Shodan analysis
   - Private IPs are skipped (192.168.x.x, 10.x.x.x, etc.)

2. **Domains**:
   - Searches for all associated infrastructure
   - Requires paid plan for search functionality

3. **Results Location**:
   ```python
   result['sources']['shodan'] = {
       'status': 'success',
       'data': {
           'org': 'Google LLC',
           'country_code': 'US',
           'ports': [53, 443],
           'vulns': {...},
           ...
       }
   }
   ```

4. **Vulnerability Extraction**:
   ```python
   if 'vulns' in shodan_data:
       result['vulnerabilities'] = len(shodan_data['vulns'])
   ```

## Example Output

When analyzing `8.8.8.8` (Google Public DNS):

```json
{
  "status": "success",
  "data": {
    "ip_str": "8.8.8.8",
    "org": "Google LLC",
    "country_name": "United States",
    "city": "Mountain View",
    "ports": [53, 443],
    "hostnames": ["dns.google"],
    "domains": ["dns.google"],
    "data": [
      {
        "port": 53,
        "transport": "tcp",
        "dns": {"recursive": true},
        "timestamp": "2025-10-30T23:18:17.132721"
      },
      {
        "port": 443,
        "transport": "tcp",
        "ssl": {
          "cert": {
            "subject": {"CN": "dns.google"},
            "issuer": {"O": "Google Trust Services"},
            "version": 3
          }
        }
      }
    ],
    "vulns": {}
  }
}
```

## Limitations & Considerations

### Free Tier Limitations
- Very limited API queries (1 credit)
- No search functionality
- Basic data only
- Not suitable for production

### Rate Limits (Paid Tier)
- 100 query credits/month (Membership plan)
- 1 request per second
- Plan accordingly for batch analysis

### Data Accuracy
- Shodan scans periodically, data may be slightly outdated
- Some services may have changed since last scan
- Always cross-reference with other sources

### Private IP Handling
- Shodan only has data on public IPs
- Our implementation automatically skips private IPs
- No API credits wasted on private addresses

## Resources

- **Official Website**: https://www.shodan.io
- **Documentation**: https://developer.shodan.io
- **API Documentation**: https://developer.shodan.io/api
- **Python Library**: https://github.com/achillean/shodan-python
- **Account Dashboard**: https://account.shodan.io
- **Pricing**: https://account.shodan.io/billing

## Support

For issues with Shodan integration:

1. Check API key configuration in `config/api_keys.json`
2. Verify API key validity at https://account.shodan.io
3. Check rate limits and remaining credits
4. Review logs for specific error messages
5. Consult Shodan documentation for API changes

---

**Last Updated**: October 2025
**Integration Status**: ✅ Fully Implemented & Production Ready
