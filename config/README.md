# API Configuration Guide

## Configuration File Structure

The `api_keys.json` file contains API credentials and configuration for various threat intelligence services.

## Censys Configuration

Censys supports multiple configuration formats:

### Option 1: Full Configuration (Recommended)

```json
{
  "censys": {
    "personal_access_token": "your_censys_personal_access_token_here",
    "organization_id": "your_organization_id_here",
    "results_per_page": 5,
    "max_services": 3
  }
}
```

**Parameters:**
- `personal_access_token` (required): Your Censys Personal Access Token (PAT)
- `organization_id` (optional): Your Censys organization ID
- `results_per_page` (optional): Number of results per page (default: 5, range: 1-100)
- `max_services` (optional): Maximum services to extract per host (default: 3)

### Option 2: Simple PAT-only Configuration

```json
{
  "censys": "your_censys_personal_access_token_here"
}
```

If you only provide a string, it will be treated as the Personal Access Token.

### Option 3: Legacy Configuration with Separate Options (Deprecated)

```json
{
  "censys": {
    "personal_access_token": "your_token",
    "organization_id": "your_org_id"
  },
  "censys_options": {
    "results_per_page": 10,
    "max_services": 5
  }
}
```

**Note:** Options in `censys` take precedence over `censys_options`. This format is maintained for backward compatibility but is not recommended for new configurations.

## Other Services

### VirusTotal
```json
{
  "virustotal": "your_virustotal_api_key_here"
}
```

### Shodan
```json
{
  "shodan": "your_shodan_api_key_here"
}
```

### URLVoid
```json
{
  "urlvoid": "your_urlvoid_api_key_here"
}
```

### AbuseIPDB
```json
{
  "abuseipdb": "your_abuseipdb_api_key_here"
}
```

### Netlas
```json
{
  "netlas": "your_netlas_api_key_here"
}
```

### IPInfo
```json
{
  "ipinfo": "your_ipinfo_token_here"
}
```

### MaxMind
```json
{
  "maxmind": {
    "license_key": "your_maxmind_license_key_here",
    "account_id": "your_maxmind_account_id_here"
  }
}
```

## Getting API Keys

- **Censys**: https://search.censys.io/account/api
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **Shodan**: https://account.shodan.io/
- **URLVoid**: https://www.urlvoid.com/api/
- **AbuseIPDB**: https://www.abuseipdb.com/api
- **Netlas**: https://app.netlas.io/profile/
- **IPInfo**: https://ipinfo.io/account/token
- **MaxMind**: https://www.maxmind.com/en/accounts/current/license-key

## Security Best Practices

1. **Never commit** `api_keys.json` to version control
2. Use the provided `api_keys.json.example` as a template
3. Set appropriate file permissions: `chmod 600 config/api_keys.json`
4. Rotate API keys regularly
5. Use environment variables for production deployments

## Example Complete Configuration

```json
{
  "virustotal": "your_virustotal_api_key_here",
  "shodan": "your_shodan_api_key_here",
  "urlvoid": "your_urlvoid_api_key_here",
  "abuseipdb": "your_abuseipdb_api_key_here",
  "censys": {
    "personal_access_token": "your_censys_personal_access_token_here",
    "organization_id": "your_organization_id_here",
    "results_per_page": 5,
    "max_services": 3
  },
  "netlas": "your_netlas_api_key_here",
  "ipinfo": "your_ipinfo_token_here",
  "maxmind": {
    "license_key": "your_maxmind_license_key_here",
    "account_id": "your_maxmind_account_id_here"
  }
}
```
