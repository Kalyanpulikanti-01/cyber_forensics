# Censys.io Integration

## Why We Use It

Censys.io is a powerful internet search engine that provides comprehensive visibility into internet-connected devices and infrastructure. It complements VirusTotal and Netlas.io by offering real-time data about hosts, certificates, and services across the internet, making it invaluable for forensic investigations and infrastructure mapping.

## What We Get

Censys.io provides rich infrastructure intelligence:

- **Host Discovery**: Find all IP addresses associated with a domain.
- **Geolocation Data**: Country, city, and coordinates of each host.
- **Autonomous System Information (ASN)**: ASN number and organization name.
- **Service Detection**: Open ports, service names, and transport protocols.
- **SSL/TLS Certificates**: Certificate details for HTTPS services.
- **Infrastructure Mapping**: Complete technical footprint of a domain.

## How It Helps the Project

Censys.io strengthens our forensic analysis toolkit by:

- **Infrastructure Discovery**: Map all internet-facing infrastructure associated with suspicious domains.
- **Service Enumeration**: Identify running services (web servers, SSH, databases, etc.) to reveal misconfigurations.
- **Attribution**: ASN and geolocation data help attribute infrastructure to specific providers or regions.
- **Validation**: Cross-reference findings from other threat intelligence sources.
- **Evidence Gathering**: Collect detailed technical data for forensic reports.

## Plans and Pricing

### Free Tier (Community)

- **API Access**: Limited monthly queries.
- **Lookup Endpoints**: Access to host lookup by IP address.
- **Limitations**: No search API access; requires Organization ID for domain searches (available with paid plans or research grants).

### Paid Plans

- **Professional/Team Plans**: Full search API access, higher quotas, organization features ($99-$299/month).
- **Research Access**: Free access for qualifying academic institutions and researchers. Apply at: https://censys.io/contact

### Current Implementation

Our toolkit uses the Censys Platform API with Personal Access Token (PAT) authentication. Search functionality requires an Organization ID (paid plan or research access). Without it, the integration will skip Censys checks gracefully with a warning.

## Configuration

In `config/api_keys.json`:

```json
{
  "censys": {
    "personal_access_token": "your_censys_pat_here",
    "organization_id": "your_org_id_here"
  }
}
```

Or simplified format:

```json
{
  "censys": "your_censys_pat_here"
}
```

**Note**: The `organization_id` is required for search API access.

## Testing the Integration

After configuration, test the integration:

```bash
python test_censys.py
```

The test script will validate your API credentials and demonstrate the data returned by Censys.

## Resources

- **Official Website**: https://censys.io
- **Documentation**: https://censys.io/docs
- **Research Access**: https://censys.io/contact
- **Python SDK**: https://github.com/censys/censys-platform-python
