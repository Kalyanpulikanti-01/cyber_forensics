#!/usr/bin/env python3
"""
Threat Intelligence Module

This module provides threat intelligence analysis capabilities including:
- VirusTotal API integration for URL/domain/IP reputation
- URLVoid API integration for multi-engine scanning
- AbuseIPDB integration for IP reputation
- Threat scoring and risk assessment
- IOC (Indicators of Compromise) analysis

Owner: Samyama.ai - Vaidhyamegha Private Limited
Contact: madhulatha@samyama.ai
Website: https://Samyama.ai
License: Proprietary - All Rights Reserved
Version: 1.0.0
Last Updated: October 2025
"""

import asyncio
import json
import logging
import time
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64

try:
    import requests
    from netlas import Netlas
    from netlas.exception import APIError
except ImportError as e:
    logging.warning(f"Some threat intelligence dependencies not available: {e}")

logger = logging.getLogger(__name__)

# Import Censys Platform SDK (v3 API with PAT support)
# Note: Legacy censys package (v2 API) is deprecated and no longer supports PAT authentication
# Import check is done lazily to allow proper logger configuration
try:
    from censys_platform import SDK as CensysPlatformSDK
    CENSYS_PLATFORM_AVAILABLE = True
except ImportError:
    CensysPlatformSDK = None
    CENSYS_PLATFORM_AVAILABLE = False
    # Warning will be logged when Censys is actually used, not at import time


class ThreatIntelligence:
    """Threat intelligence gathering and analysis."""

    # Configuration constants
    DEFAULT_CENSYS_RESULTS_PER_PAGE = 5
    DEFAULT_CENSYS_MAX_SERVICES = 3

    # Domain validation pattern - matches lowercase alphanumeric labels separated by dots
    # Note: Input is normalized to lowercase before validation (RFC 1035 domains are case-insensitive)
    # Pattern enforces: no leading/trailing dots or hyphens, max 63 chars per label
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
    )

    def __init__(self, config: Dict[str, Any]):
        """Initialize threat intelligence analyzer with configuration.

        Censys Configuration (3 supported formats):
        
        1. Full configuration (RECOMMENDED):
           config['api_keys']['censys'] = {
               'personal_access_token': 'your_token',
               'organization_id': 'your_org_id',  # optional
               'results_per_page': 5,  # optional, default: 5
               'max_services': 3  # optional, default: 3
           }
        
        2. Simple PAT-only configuration:
           config['api_keys']['censys'] = 'your_token'
        
        3. Legacy with separate options (DEPRECATED):
           config['api_keys']['censys'] = {'personal_access_token': 'your_token'}
           config['censys_options'] = {'results_per_page': 5, 'max_services': 3}
        
        Note: Options in config['api_keys']['censys'] take precedence over config['censys_options'].
        See config/README.md for detailed configuration guide.
        """
        self.config = config
        self.timeout = config.get('timeouts', {}).get('threat_intel', 60)
        self.session = requests.Session()
        self.session.timeout = self.timeout

        # API keys from config
        self.api_keys = config.get('api_keys', {})
        
        # Censys configuration options
        # Check in api_keys['censys'] first (preferred), then fall back to censys_options (backward compatibility)
        censys_api_config = self.api_keys.get('censys', {})
        censys_options_config = config.get('censys_options', {})
        
        # If censys is a dict, it may contain options; otherwise use censys_options
        if isinstance(censys_api_config, dict):
            results_per_page = censys_api_config.get('results_per_page') or censys_options_config.get('results_per_page') or self.DEFAULT_CENSYS_RESULTS_PER_PAGE
            max_services = censys_api_config.get('max_services') or censys_options_config.get('max_services') or self.DEFAULT_CENSYS_MAX_SERVICES
        else:
            # If censys is a string (PAT), use censys_options
            results_per_page = censys_options_config.get('results_per_page') or self.DEFAULT_CENSYS_RESULTS_PER_PAGE
            max_services = censys_options_config.get('max_services') or self.DEFAULT_CENSYS_MAX_SERVICES
        
        # Validate and clamp to valid ranges
        self.censys_results_per_page = max(1, min(100, results_per_page))  # Censys API limit: 1-100
        self.censys_max_services = max(1, max_services)  # At least 1 service
        self.virustotal_key = self.api_keys.get('virustotal')
        self.urlvoid_key = self.api_keys.get('urlvoid')
        self.abuseipdb_key = self.api_keys.get('abuseipdb')
        self.netlas_key = self.api_keys.get('netlas')
        
        # Censys can be either PAT (string) or old-style credentials (dict)
        censys_config = self.api_keys.get('censys', {})
        if isinstance(censys_config, str):
            self.censys_token = censys_config  # Personal Access Token
            self.censys_org_id = None
            self.censys_id = None
            self.censys_secret = None
        else:
            self.censys_token = censys_config.get('token') or censys_config.get('personal_access_token')
            self.censys_org_id = censys_config.get('organization_id') or censys_config.get('org_id')
            self.censys_id = censys_config.get('api_id')
            self.censys_secret = censys_config.get('api_secret')
        
        # API endpoints
        self.virustotal_url_api = "https://www.virustotal.com/api/v3/urls"
        self.virustotal_domain_api = "https://www.virustotal.com/api/v3/domains"
        self.virustotal_ip_api = "https://www.virustotal.com/api/v3/ip_addresses"
        self.abuseipdb_api = "https://api.abuseipdb.com/api/v2/check"
        
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive threat intelligence analysis on a URL."""
        result = {
            'url': url,
            'virustotal': {},
            'urlvoid': {},
            'threat_score': 0,
            'is_malicious': False,
            'threat_categories': [],
            'recommendations': []
        }
        
        try:
            # Run all threat intelligence checks concurrently
            vt_task = self._check_virustotal_url(url)
            
            # Wait for results
            result['virustotal'] = await vt_task
            
            # Calculate overall threat score
            result = await self._calculate_threat_score(result)
            
        except Exception as e:
            logger.error(f"Threat intelligence analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation."""
        
        # Extract domain if a full URL is provided
        try:
            parsed_url = urlparse(domain)
            if parsed_url.netloc:
                domain = parsed_url.netloc
        except Exception:
            pass  # Assume it's already a domain
        result = {
            'domain': domain,
            'virustotal': {},
            'netlas': {},
            'censys': {},
            'threat_score': 0,
            'is_malicious': False,
            'categories': [],
            'last_analysis_stats': {}
        }
        
        try:
            tasks = []
            if self.virustotal_key:
                tasks.append(self._check_virustotal_domain(domain))
            else:
                tasks.append(asyncio.sleep(0))

            if self.netlas_key:
                tasks.append(self._check_netlas_domain(domain))
            else:
                tasks.append(asyncio.sleep(0))

            if self.censys_token or (self.censys_id and self.censys_secret):
                tasks.append(self._check_censys_domain(domain))
            else:
                tasks.append(asyncio.sleep(0))

            vt_result, netlas_result, censys_result = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle VirusTotal results
            if not isinstance(vt_result, Exception) and vt_result:
                result['virustotal'] = vt_result

            # Handle Netlas results - function already returns properly structured dict
            if isinstance(netlas_result, Exception):
                result['netlas'] = {'available': False, 'error': str(netlas_result)}
            elif netlas_result and isinstance(netlas_result, dict):
                result['netlas'] = netlas_result
            else:
                result['netlas'] = {'available': False, 'error': 'No data returned from Netlas'}

            # Handle Censys results - function already returns properly structured dict
            if isinstance(censys_result, Exception):
                result['censys'] = {'available': False, 'error': str(censys_result)}
            elif censys_result and isinstance(censys_result, dict):
                result['censys'] = censys_result
            else:
                result['censys'] = {'available': False, 'error': 'No data returned from Censys'}

            # Extract key information
            if 'data' in result.get('virustotal', {}):
                    data = result['virustotal']['data']
                    attributes = data.get('attributes', {})
                    
                    result['last_analysis_stats'] = attributes.get('last_analysis_stats', {})
                    result['categories'] = attributes.get('categories', {})
                    result['reputation'] = attributes.get('reputation', 0)
                    
                    # Determine if malicious
                    stats = result['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    suspicious_count = stats.get('suspicious', 0)
                    
                    if malicious_count > 0 or suspicious_count > 2:
                        result['is_malicious'] = True
                        result['threat_score'] = min(100, (malicious_count * 10) + (suspicious_count * 5))
            
        except Exception as e:
            logger.error(f"Domain analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def analyze_ip(self, ip: str) -> Dict[str, Any]:
        """Analyze IP address reputation."""
        result = {
            'ip': ip,
            'virustotal': {},
            'abuseipdb': {},
            'threat_score': 0,
            'is_malicious': False,
            'abuse_confidence': 0
        }
        
        try:
            # Run checks concurrently
            tasks = []
            
            if self.virustotal_key:
                tasks.append(self._check_virustotal_ip(ip))
            else:
                tasks.append(asyncio.sleep(0))  # Placeholder
            
            if self.abuseipdb_key:
                tasks.append(self._check_abuseipdb(ip))
            else:
                tasks.append(asyncio.sleep(0))  # Placeholder
            
            vt_result, abuse_result = await asyncio.gather(*tasks, return_exceptions=True)
            
            if not isinstance(vt_result, Exception) and vt_result:
                result['virustotal'] = vt_result
            
            if not isinstance(abuse_result, Exception) and abuse_result:
                result['abuseipdb'] = abuse_result
                result['abuse_confidence'] = abuse_result.get('data', {}).get('abuseConfidenceScore', 0)
            
            # Calculate threat score
            if result['abuse_confidence'] > 50:
                result['is_malicious'] = True
                result['threat_score'] = result['abuse_confidence']
            
        except Exception as e:
            logger.error(f"IP analysis failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Check URL reputation using VirusTotal API v3."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.virustotal_key:
            result['error'] = 'VirusTotal API key not configured'
            return result
        
        try:
            # Step 1: Submit URL for scanning
            headers = {
                'x-apikey': self.virustotal_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {'url': url}
            response = self.session.post(
                self.virustotal_url_api,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                submission_data = response.json()
                
                # Step 2: Get the URL ID
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                
                # Step 3: Wait a bit for analysis to complete
                await asyncio.sleep(2)
                
                # Step 4: Get analysis results
                analysis_url = f"{self.virustotal_url_api}/{url_id}"
                analysis_response = self.session.get(
                    analysis_url,
                    headers={'x-apikey': self.virustotal_key},
                    timeout=self.timeout
                )
                
                if analysis_response.status_code == 200:
                    result['available'] = True
                    result['data'] = analysis_response.json()
                else:
                    result['error'] = f"Analysis retrieval failed: {analysis_response.status_code}"
            else:
                result['error'] = f"URL submission failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"VirusTotal URL check failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _check_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation using VirusTotal API v3."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.virustotal_key:
            result['error'] = 'VirusTotal API key not configured'
            return result
        
        try:
            headers = {'x-apikey': self.virustotal_key}
            url = f"{self.virustotal_domain_api}/{domain}"
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result['available'] = True
                result['data'] = response.json()
            elif response.status_code == 404:
                result['error'] = 'Domain not found in VirusTotal database'
            else:
                result['error'] = f"Request failed: {response.status_code}"

        except Exception as e:
            logger.error(f"VirusTotal domain check failed: {e}")
            result['error'] = str(e)

        return result
    
    async def _check_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using VirusTotal API v3."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.virustotal_key:
            result['error'] = 'VirusTotal API key not configured'
            return result
        
        try:
            headers = {'x-apikey': self.virustotal_key}
            url = f"{self.virustotal_ip_api}/{ip}"
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result['available'] = True
                result['data'] = response.json()
            elif response.status_code == 404:
                result['error'] = 'IP not found in VirusTotal database'
            else:
                result['error'] = f"Request failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"VirusTotal IP check failed: {e}")
            result['error'] = str(e)
        
        return result

    async def _check_netlas_domain(self, domain: str) -> Dict[str, Any]:
        """Get domain details from Netlas.io."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }

        if not self.netlas_key:
            result['error'] = 'Netlas.io API key not configured'
            return result

        try:
            netlas_connection = Netlas(api_key=self.netlas_key)
            loop = asyncio.get_running_loop()
            netlas_data = await loop.run_in_executor(None, netlas_connection.host, domain)
            result['available'] = True
            result['data'] = netlas_data
        except APIError as e:
            logger.error(f"Netlas.io API error. This is likely due to an invalid API key. Error: {e}")
            result['error'] = 'Netlas.io API key is invalid or has expired.'
        except Exception as e:
            logger.error(f"Netlas.io domain check failed: {e}", exc_info=True)
            result['error'] = f"An exception occurred: {type(e).__name__} - {e}"

        return result
    
    async def _check_censys_domain(self, domain: str) -> Dict[str, Any]:
        """Get domain details from Censys using Platform API SDK."""
        result = {
            'available': False,
            'data': [],
            'error': None
        }

        # Validate domain input
        if not domain or not isinstance(domain, str):
            result['error'] = 'Invalid domain provided'
            return result

        # Domain sanitization - remove whitespace and convert to lowercase
        domain = domain.strip().lower()

        # Length validation (RFC 1035: max 253 characters total, 63 per label)
        if len(domain) > 253 or len(domain) < 1:
            result['error'] = 'Domain length must be between 1 and 253 characters'
            return result

        # Validate domain format using RFC 1035 compliant regex
        if not self.DOMAIN_PATTERN.match(domain):
            result['error'] = 'Invalid domain format. Domain must contain only alphanumeric characters, hyphens, and dots. Labels cannot start or end with hyphens, and consecutive dots are not allowed.'
            return result

        # Check if we have PAT token
        if not self.censys_token:
            result['error'] = 'Censys Personal Access Token (PAT) not configured'
            return result

        # Check if Platform SDK is available
        if not CENSYS_PLATFORM_AVAILABLE or CensysPlatformSDK is None:
            result['error'] = 'Censys Platform SDK not installed. Run: pip install censys-platform'
            return result

        # Check if organization ID is available (required for search API)
        if not self.censys_org_id:
            result['error'] = 'Censys search API requires Organization ID (available with paid plans or research accounts). This integration uses the search API which is not available on the free tier. For research access, visit: https://censys.io/contact'
            logger.warning("Censys Organization ID not configured. Search API requires paid plan or research access. Skipping Censys check.")
            return result

        try:
            query = f"services.dns.names.name:{domain}"
            logger.info(f"Censys: Searching with query: {query}")

            # Execute search in thread pool to avoid blocking
            loop = asyncio.get_running_loop()

            def search_censys() -> List[Dict[str, Any]]:
                """Search Censys in synchronous context."""
                # Initialize Platform SDK with PAT
                from censys_platform.models import SearchQueryInputBody

                # Initialize SDK with organization ID if available
                sdk_kwargs = {'personal_access_token': self.censys_token}
                if self.censys_org_id:
                    sdk_kwargs['organization_id'] = self.censys_org_id

                with CensysPlatformSDK(**sdk_kwargs) as sdk:
                    # Create search query body
                    search_body = SearchQueryInputBody(
                        query=query,
                        per_page=self.censys_results_per_page,
                        cursor="",  # Start from beginning
                    )

                    # Search using global_data module (org_id passed automatically from SDK init)
                    search_response = sdk.global_data.search(
                        search_query_input_body=search_body
                    )

                    # Extract results from response object
                    if hasattr(search_response, 'result'):
                        hits = search_response.result.hits if hasattr(search_response.result, 'hits') else []
                    elif isinstance(search_response, dict):
                        hits = search_response.get('result', {}).get('hits', [])
                    else:
                        hits = []

                    return hits

            # Run blocking Censys SDK call in dedicated thread pool with proper timeout
            # Note: Using ThreadPoolExecutor with future.result(timeout) instead of asyncio.wait_for
            # because asyncio.wait_for cannot actually kill threads - it only raises an exception
            # while the thread continues to run. future.result(timeout) properly handles thread timeout.
            # Manual executor management (not context manager) to ensure non-blocking shutdown on timeout
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(search_censys)
                try:
                    search_results = future.result(timeout=self.timeout)
                except TimeoutError:
                    result['error'] = f'Censys search timed out after {self.timeout} seconds'
                    logger.error(f"Censys search timeout for domain: {domain}")
                    return result
            finally:
                # Shutdown without waiting for timed-out threads to complete
                executor.shutdown(wait=False, cancel_futures=True)

            logger.info(f"Censys: Found {len(search_results)} hosts")

            # Extract key information from each host
            for hit in search_results:
                host_data = {
                    'ip': hit.get('ip'),
                    'location': hit.get('location', {}),
                    'autonomous_system': hit.get('autonomous_system', {}),
                    'services': []
                }

                # Extract service information (configurable limit)
                if 'services' in hit:
                    for service in hit.get('services', [])[:self.censys_max_services]:
                        service_info = {
                            'port': service.get('port'),
                            'service_name': service.get('service_name'),
                            'transport_protocol': service.get('transport_protocol')
                        }
                        host_data['services'].append(service_info)

                result['data'].append(host_data)
                logger.info(f"Censys: Found host {host_data['ip']}")

            if result['data']:
                result['available'] = True
            else:
                result['error'] = 'No hosts found for this domain'

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Censys domain check failed: {e}", exc_info=True)

            # Provide helpful error messages
            if '401' in error_msg or 'Unauthorized' in error_msg or 'authentication' in error_msg.lower():
                result['error'] = 'Authentication failed - check your Censys Personal Access Token (PAT)'
            elif '429' in error_msg or 'rate limit' in error_msg.lower():
                result['error'] = 'Rate limit exceeded - please wait before making more requests'
            elif 'organization' in error_msg.lower():
                result['error'] = 'Organization ID may be required - check if your account needs organization_id parameter'
            else:
                result['error'] = f"An exception occurred: {type(e).__name__} - {e}"

        return result

    async def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB API."""
        result = {
            'available': False,
            'data': {},
            'error': None
        }
        
        if not self.abuseipdb_key:
            result['error'] = 'AbuseIPDB API key not configured'
            return result
        
        try:
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = self.session.get(
                self.abuseipdb_api,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result['available'] = True
                result['data'] = response.json()
            else:
                result['error'] = f"Request failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _calculate_threat_score(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall threat score based on all intelligence sources."""
        total_score = 0
        threat_categories = []
        
        # VirusTotal scoring
        if result['virustotal'].get('available'):
            vt_data = result['virustotal'].get('data', {})
            
            if 'data' in vt_data:
                attributes = vt_data['data'].get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                if malicious > 0:
                    total_score += min(50, malicious * 5)
                    threat_categories.append('malicious')
                
                if suspicious > 0:
                    total_score += min(25, suspicious * 3)
                    threat_categories.append('suspicious')
                
                # Check categories
                categories = attributes.get('categories', {})
                if 'phishing' in str(categories).lower():
                    threat_categories.append('phishing')
                    total_score += 20
                
                if 'malware' in str(categories).lower():
                    threat_categories.append('malware')
                    total_score += 25
        
        result['threat_score'] = min(100, total_score)
        result['threat_categories'] = list(set(threat_categories))
        
        # Determine if malicious
        if result['threat_score'] >= 50:
            result['is_malicious'] = True
            result['recommendations'].append('⚠️ HIGH RISK: Multiple threat intelligence sources flag this as malicious')
        elif result['threat_score'] >= 30:
            result['is_malicious'] = False
            result['recommendations'].append('⚠️ MEDIUM RISK: Some suspicious indicators detected')
        else:
            result['recommendations'].append('✓ LOW RISK: No significant threats detected')
        
        return result
    
    async def batch_analyze(self, items: List[str], item_type: str = 'url') -> Dict[str, Any]:
        """Batch analyze multiple items (URLs, domains, or IPs)."""
        results = {
            'total': len(items),
            'analyzed': 0,
            'malicious': 0,
            'clean': 0,
            'errors': 0,
            'items': []
        }
        
        try:
            tasks = []
            
            for item in items:
                if item_type == 'url':
                    tasks.append(self.analyze_url(item))
                elif item_type == 'domain':
                    tasks.append(self.analyze_domain(item))
                elif item_type == 'ip':
                    tasks.append(self.analyze_ip(item))
            
            # Execute all tasks concurrently
            item_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for item, item_result in zip(items, item_results):
                if isinstance(item_result, Exception):
                    results['errors'] += 1
                    results['items'].append({
                        'item': item,
                        'error': str(item_result)
                    })
                else:
                    results['analyzed'] += 1
                    if item_result.get('is_malicious'):
                        results['malicious'] += 1
                    else:
                        results['clean'] += 1
                    results['items'].append(item_result)
            
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def extract_iocs(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise (IOCs) from analysis data."""
        iocs = {
            'urls': [],
            'domains': [],
            'ips': [],
            'hashes': [],
            'emails': []
        }
        
        try:
            # Extract from VirusTotal data
            if 'virustotal' in data and data['virustotal'].get('available'):
                vt_data = data['virustotal'].get('data', {})
                
                if 'data' in vt_data:
                    attributes = vt_data['data'].get('attributes', {})
                    
                    # Extract related URLs
                    if 'last_final_url' in attributes:
                        iocs['urls'].append(attributes['last_final_url'])
                    
                    # Extract domains
                    if 'domain' in data:
                        iocs['domains'].append(data['domain'])
                    
                    # Extract IPs
                    if 'ip' in data:
                        iocs['ips'].append(data['ip'])
            
        except Exception as e:
            logger.error(f"IOC extraction failed: {e}")
        
        return iocs
