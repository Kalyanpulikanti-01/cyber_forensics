# Censys.io Integration

## Why We Use It

Censys.io is a powerful internet search engine that provides comprehensive visibility into internet-connected devices and infrastructure. We use it as a complementary threat intelligence source alongside VirusTotal and Netlas.io to gather deep technical insights about domain infrastructure, hosting environments, and exposed services. Censys excels at providing real-time data about hosts, certificates, and services across the internet, making it invaluable for forensic investigations.

## What We Get

Censys.io provides rich infrastructure intelligence, including:

- **Host Discovery**: Find all hosts (IP addresses) associated with a domain.
- **Geolocation Data**: Country, city, and coordinates of each host.
- **Autonomous System Information (ASN)**: ASN number and organization name.
- **Service Detection**: Open ports, service names, and transport protocols.
- **SSL/TLS Certificates**: Certificate details for HTTPS services.
- **Infrastructure Mapping**: Understand the technical footprint of a domain.
- **Cloud Provider Detection**: Identify hosting on AWS, GCP, Azure, or other providers.

## How It Helps the Project

Censys.io strengthens our forensic analysis toolkit by:

- **Infrastructure Discovery**: Map out all internet-facing infrastructure associated with a suspicious domain, revealing the hosting environment and potential attack surface.
- **Service Enumeration**: Identify what services are running on discovered hosts (web servers, SSH, databases, etc.), which can reveal misconfigurations or unusual setups typical of malicious infrastructure.
- **Attribution**: ASN and geolocation data help attribute infrastructure to specific hosting providers or geographic regions, useful for identifying patterns in phishing campaigns.
- **Validation**: Cross-reference findings from other threat intelligence sources (VirusTotal, Netlas) to build a complete picture.
- **Evidence Gathering**: Collect detailed technical data points that can be included in forensic reports.

## Plans and Pricing

Censys offers different access tiers with varying capabilities. The project uses the **Censys Platform API** with Personal Access Token (PAT) authentication.

### Free Tier (Community)

- **API Access**: Limited number of queries per month (exact limits vary).
- **Lookup Endpoints**: Access to host lookup by IP address.
- **Features**: Basic host information, geolocation, and service data.
- **Limitations**:
  - **No Search API**: Cannot perform search queries like `services.dns.names.name:example.com` on the free tier.
  - **Organization ID Required for Search**: Search capabilities require organization access (paid plan or research grant).
  - Best suited for targeted lookups when you already know the IP addresses.

### Paid Plans

Censys offers several paid tiers for users who need advanced search and higher quotas:

- **Professional/Team Plans**:
  - **Search API Access**: Full search capabilities across all Censys datasets.
  - **Higher Quotas**: Increased daily/monthly request limits.
  - **Organization Features**: Multi-user access, team management.
  - **Cost**: Typically starts at $99-$299/month depending on usage.

- **Research Access**:
  - **Academic/Non-Profit**: Censys offers free research access to qualifying academic institutions and researchers.
  - **Application Required**: Must apply through their website: https://censys.io/contact
  - **Benefits**: Access to search API with reasonable quotas for research purposes.

### Current Implementation

Our toolkit currently implements Censys with the following considerations:

- **Authentication**: Uses Personal Access Token (PAT) for authentication.
- **Search Requirements**: The search API requires an Organization ID, which is only available with paid plans or research access.
- **Fallback Behavior**: If Organization ID is not configured, the integration will log a warning and skip Censys checks gracefully.
- **Free Tier Note**: Users on the free tier can still use Censys for IP lookups if they modify the code to use lookup endpoints instead of search.

## Implementation Details

### Configuration

In `config/api_keys.json`, configure Censys credentials:

```json
{
  "censys": {
    "personal_access_token": "your_censys_pat_here",
    "organization_id": "your_org_id_here"
  }
}
```

Or use the simplified format:

```json
{
  "censys": "your_censys_pat_here"
}
```

**Note**: The `organization_id` field is required for search API access. Without it, Censys integration will be skipped with a warning message.

### What Gets Analyzed

When analyzing a domain, Censys performs a search query to find all hosts with DNS names matching the target domain. For each discovered host, we extract:

1. **IP Address**: The primary IPv4 address of the host.
2. **Location**: Geographic location including city, country, and coordinates.
3. **Autonomous System**: ASN number and organization name.
4. **Services**: Up to 3 services per host, including:
   - Port number
   - Service name (e.g., HTTP, SSH, MySQL)
   - Transport protocol (TCP/UDP)

### Example Output

```json
{
  "censys": {
    "available": true,
    "data": [
      {
        "ip": "104.21.45.123",
        "location": {
          "city": "San Francisco",
          "country": "United States",
          "coordinates": {"latitude": 37.7749, "longitude": -122.4194}
        },
        "autonomous_system": {
          "asn": 13335,
          "name": "CLOUDFLARENET"
        },
        "services": [
          {
            "port": 443,
            "service_name": "HTTP",
            "transport_protocol": "TCP"
          },
          {
            "port": 80,
            "service_name": "HTTP",
            "transport_protocol": "TCP"
          }
        ]
      }
    ]
  }
}
```

## Getting Started with Censys

### For Free Tier Users

If you're on the free tier and don't have organization access:

1. **Sign up**: Create a free account at https://censys.io
2. **Generate PAT**: Go to Account Settings → API and generate a Personal Access Token.
3. **Note Limitations**: Be aware that search functionality won't work without organization access.
4. **Alternative**: Consider applying for research access if you're conducting academic or security research.

### For Paid/Research Users

1. **Sign up**: Create an account or apply for research access.
2. **Get Organization ID**: Found in your account dashboard or team settings.
3. **Generate PAT**: Create a Personal Access Token with appropriate permissions.
4. **Configure**: Add both PAT and Organization ID to `config/api_keys.json`.
5. **Test**: Run `python test_censys.py` to verify the integration.

## Why Censys Over Alternatives?

Censys stands out for several reasons:

- **Real-Time Data**: Continuously scans the internet, providing up-to-date infrastructure information.
- **Technical Depth**: Offers detailed service fingerprinting and banner information.
- **Certificate Transparency**: Extensive SSL/TLS certificate database.
- **Academic Support**: Offers free research access to qualifying users.
- **API Quality**: Well-documented, modern API with SDKs for multiple languages.
- **Complementary**: Works alongside VirusTotal and Netlas to provide different perspectives on infrastructure.

## Limitations

- **Free Tier Restrictions**: Search API requires paid plan or research access.
- **Rate Limits**: Even paid plans have query limits based on subscription tier.
- **Cost**: Can be expensive for commercial use cases requiring high query volumes.
- **Learning Curve**: More technical than some alternatives; requires understanding of internet infrastructure concepts.

## Resources

- **Official Website**: https://censys.io
- **Documentation**: https://censys.io/docs
- **Research Access**: https://censys.io/contact
- **Python SDK**: https://github.com/censys/censys-platform-python
- **Support**: support@censys.io
