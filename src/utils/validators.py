"""
Validators Module for Threat Intelligence Pipeline
Input validation and sanitization utilities
"""

import re
import ipaddress
import validators
import tldextract
from typing import Optional, List, Dict, Any, Union
from urllib.parse import urlparse
import hashlib
import phonenumbers
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class InputValidator:
    """Validates and sanitizes user inputs"""
    
    # Maximum lengths for different input types
    MAX_QUERY_LENGTH = 1000
    MAX_INDICATOR_LENGTH = 500
    MAX_CONTEXT_LENGTH = 5000
    MAX_METADATA_SIZE = 10000  # JSON string length
    
    # Regex patterns for validation
    PATTERNS = {
        'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
        'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
        'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
        'indicator_id': re.compile(r'^[a-fA-F0-9]{32}$'),
        'document_id': re.compile(r'^[a-zA-Z0-9_-]{1,255}$'),
        'campaign_name': re.compile(r'^[a-zA-Z0-9\s_-]{1,100}$'),
        'language_code': re.compile(r'^[a-z]{2}$'),
    }
    
    @classmethod
    def validate_query(cls, query: str) -> tuple[bool, str]:
        """
        Validate search query
        
        Args:
            query: Search query string
            
        Returns:
            Tuple of (is_valid, sanitized_query or error_message)
        """
        if not query:
            return False, "Query cannot be empty"
        
        # Check length
        if len(query) > cls.MAX_QUERY_LENGTH:
            return False, f"Query exceeds maximum length of {cls.MAX_QUERY_LENGTH}"
        
        # Sanitize query
        sanitized = cls._sanitize_string(query)
        
        # Check for SQL injection patterns
        if cls._contains_sql_injection(sanitized):
            return False, "Query contains invalid characters"
        
        # Check for NoSQL injection patterns
        if cls._contains_nosql_injection(sanitized):
            return False, "Query contains invalid patterns"
        
        return True, sanitized
    
    @classmethod
    def validate_indicator(cls, indicator_type: str, value: str) -> tuple[bool, str]:
        """
        Validate indicator based on type
        
        Args:
            indicator_type: Type of indicator
            value: Indicator value
            
        Returns:
            Tuple of (is_valid, normalized_value or error_message)
        """
        if not value or len(value) > cls.MAX_INDICATOR_LENGTH:
            return False, "Invalid indicator length"
        
        # Validate based on type
        validators_map = {
            'domain': cls._validate_domain,
            'url': cls._validate_url,
            'ip_address': cls._validate_ip,
            'email': cls._validate_email,
            'phone': cls._validate_phone,
            'md5': cls._validate_md5,
            'sha1': cls._validate_sha1,
            'sha256': cls._validate_sha256,
            'bitcoin': cls._validate_bitcoin,
            'ethereum': cls._validate_ethereum,
        }
        
        validator = validators_map.get(indicator_type)
        if not validator:
            return False, f"Unknown indicator type: {indicator_type}"
        
        return validator(value)
    
    @classmethod
    def validate_indicator_id(cls, indicator_id: str) -> bool:
        """Validate indicator ID format"""
        return bool(cls.PATTERNS['indicator_id'].match(indicator_id))
    
    @classmethod
    def validate_document_id(cls, doc_id: str) -> bool:
        """Validate document ID format"""
        return bool(cls.PATTERNS['document_id'].match(doc_id))
    
    @classmethod
    def validate_campaign_name(cls, name: str) -> bool:
        """Validate campaign name"""
        return bool(cls.PATTERNS['campaign_name'].match(name))
    
    @classmethod
    def validate_confidence_score(cls, score: float) -> bool:
        """Validate confidence score is between 0 and 1"""
        try:
            return 0.0 <= float(score) <= 1.0
        except (TypeError, ValueError):
            return False
    
    @classmethod
    def validate_metadata(cls, metadata: Union[Dict, str]) -> tuple[bool, Any]:
        """
        Validate metadata JSON
        
        Args:
            metadata: Metadata dictionary or JSON string
            
        Returns:
            Tuple of (is_valid, parsed_metadata or error_message)
        """
        import json
        
        if isinstance(metadata, str):
            if len(metadata) > cls.MAX_METADATA_SIZE:
                return False, "Metadata exceeds size limit"
            
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                return False, "Invalid JSON format"
        
        if not isinstance(metadata, dict):
            return False, "Metadata must be a dictionary"
        
        # Sanitize metadata values
        sanitized = cls._sanitize_dict(metadata)
        
        return True, sanitized
    
    @classmethod
    def validate_date_range(cls, date_from: str, date_to: str) -> tuple[bool, str]:
        """
        Validate date range
        
        Args:
            date_from: Start date string
            date_to: End date string
            
        Returns:
            Tuple of (is_valid, error_message or None)
        """
        try:
            start = datetime.fromisoformat(date_from)
            end = datetime.fromisoformat(date_to)
            
            if start > end:
                return False, "Start date must be before end date"
            
            # Check reasonable date range (e.g., not more than 10 years)
            if (end - start).days > 3650:
                return False, "Date range too large"
            
            return True, None
            
        except (ValueError, TypeError) as e:
            return False, f"Invalid date format: {e}"
    
    @staticmethod
    def _validate_domain(domain: str) -> tuple[bool, str]:
        """Validate domain name"""
        domain = domain.lower().strip()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        
        # Extract domain parts
        extracted = tldextract.extract(domain)
        
        if not extracted.domain or not extracted.suffix:
            return False, "Invalid domain format"
        
        # Check for valid characters
        if not re.match(r'^[a-z0-9.-]+$', domain):
            return False, "Domain contains invalid characters"
        
        # Check length
        if len(domain) > 253:
            return False, "Domain name too long"
        
        return True, domain
    
    @staticmethod
    def _validate_url(url: str) -> tuple[bool, str]:
        """Validate URL"""
        if not validators.url(url):
            return False, "Invalid URL format"
        
        # Parse and validate components
        parsed = urlparse(url)
        
        if not parsed.scheme or not parsed.netloc:
            return False, "URL missing scheme or domain"
        
        # Normalize URL
        normalized = url.lower().strip()
        
        return True, normalized
    
    @staticmethod
    def _validate_ip(ip: str) -> tuple[bool, str]:
        """Validate IP address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if it's a valid public IP (optional)
            # if ip_obj.is_private or ip_obj.is_reserved:
            #     return False, "Private or reserved IP address"
            
            return True, str(ip_obj)
            
        except ValueError:
            return False, "Invalid IP address"
    
    @staticmethod
    def _validate_email(email: str) -> tuple[bool, str]:
        """Validate email address"""
        email = email.lower().strip()
        
        if not validators.email(email):
            return False, "Invalid email format"
        
        # Additional validation
        if len(email) > 254:  # RFC 5321
            return False, "Email address too long"
        
        return True, email
    
    @staticmethod
    def _validate_phone(phone: str) -> tuple[bool, str]:
        """Validate phone number"""
        try:
            # Try to parse with phonenumbers library
            parsed = phonenumbers.parse(phone, None)
            
            if not phonenumbers.is_valid_number(parsed):
                # Try with US region as default
                parsed = phonenumbers.parse(phone, "US")
                if not phonenumbers.is_valid_number(parsed):
                    return False, "Invalid phone number"
            
            # Format to E164
            formatted = phonenumbers.format_number(
                parsed, 
                phonenumbers.PhoneNumberFormat.E164
            )
            
            return True, formatted
            
        except phonenumbers.NumberParseException:
            # Basic validation for numbers that can't be parsed
            digits_only = re.sub(r'\D', '', phone)
            if len(digits_only) >= 7 and len(digits_only) <= 15:
                return True, phone
            return False, "Invalid phone number format"
    
    @classmethod
    def _validate_md5(cls, hash_value: str) -> tuple[bool, str]:
        """Validate MD5 hash"""
        hash_value = hash_value.lower().strip()
        if cls.PATTERNS['md5'].match(hash_value):
            return True, hash_value
        return False, "Invalid MD5 hash"
    
    @classmethod
    def _validate_sha1(cls, hash_value: str) -> tuple[bool, str]:
        """Validate SHA1 hash"""
        hash_value = hash_value.lower().strip()
        if cls.PATTERNS['sha1'].match(hash_value):
            return True, hash_value
        return False, "Invalid SHA1 hash"
    
    @classmethod
    def _validate_sha256(cls, hash_value: str) -> tuple[bool, str]:
        """Validate SHA256 hash"""
        hash_value = hash_value.lower().strip()
        if cls.PATTERNS['sha256'].match(hash_value):
            return True, hash_value
        return False, "Invalid SHA256 hash"
    
    @staticmethod
    def _validate_bitcoin(address: str) -> tuple[bool, str]:
        """Validate Bitcoin address"""
        # Basic Bitcoin address validation (P2PKH and P2SH)
        pattern = re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}')
        
        if pattern.match(address):
            # Could add checksum validation here
            return True, address
        
        # Check for Bech32 format (SegWit)
        if address.startswith('bc1') and len(address) >= 42:
            return True, address
        
        return False, "Invalid Bitcoin address"
    
    @staticmethod
    def _validate_ethereum(address: str) -> tuple[bool, str]:
        """Validate Ethereum address"""
        # Ethereum address validation
        pattern = re.compile(r'^0x[a-fA-F0-9]{40}')
        
        if pattern.match(address):
            # Normalize to lowercase
            return True, address.lower()
        
        return False, "Invalid Ethereum address"
    
    @staticmethod
    def _sanitize_string(text: str) -> str:
        """Sanitize string input"""
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Strip whitespace
        text = text.strip()
        
        # Remove control characters except newlines and tabs
        text = ''.join(
            char for char in text 
            if char == '\n' or char == '\t' or not ord(char) < 32
        )
        
        return text
    
    @classmethod
    def _sanitize_dict(cls, data: Dict) -> Dict:
        """Recursively sanitize dictionary values"""
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            if isinstance(key, str):
                key = cls._sanitize_string(key)
            
            # Sanitize value
            if isinstance(value, str):
                value = cls._sanitize_string(value)
            elif isinstance(value, dict):
                value = cls._sanitize_dict(value)
            elif isinstance(value, list):
                value = [
                    cls._sanitize_string(item) if isinstance(item, str) else item
                    for item in value
                ]
            
            sanitized[key] = value
        
        return sanitized
    
    @staticmethod
    def _contains_sql_injection(text: str) -> bool:
        """Check for potential SQL injection patterns"""
        sql_patterns = [
                r';\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\s+',
                r'--\s*',
                r'\/\*.*\*\/',
                r'(UNION|SELECT).*(FROM|WHERE)',
                r'OR\s+\d+=\d+',
                r'OR\s+\'[^\']*\'\s*=\s*\'[^\']*\'',
            ]
        
        text_upper = text.upper()
        for pattern in sql_patterns:
            if re.search(pattern, text_upper, re.IGNORECASE):
                return True
        
        return False
    
    @staticmethod
    def _contains_nosql_injection(text: str) -> bool:
        """Check for potential NoSQL injection patterns"""
        nosql_patterns = [
            r'\$where',
            r'\$ne',
            r'\$gt',
            r'\$regex',
            r'function\s*\(',
            r'this\.',
            r'db\.',
            r'sleep\s*\(',
        ]
        
        for pattern in nosql_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False


class FileValidator:
    """Validates file uploads and paths"""
    
    ALLOWED_EXTENSIONS = {'.pdf', '.txt', '.json', '.csv'}
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    @classmethod
    def validate_file_path(cls, file_path: str) -> tuple[bool, str]:
        """
        Validate file path
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (is_valid, error_message or normalized_path)
        """
        import os
        from pathlib import Path
        
        try:
            path = Path(file_path).resolve()
            
            # Check for path traversal
            if '..' in file_path:
                return False, "Path traversal detected"
            
            # Check file exists
            if not path.exists():
                return False, "File does not exist"
            
            # Check file extension
            if path.suffix.lower() not in cls.ALLOWED_EXTENSIONS:
                return False, f"File type {path.suffix} not allowed"
            
            # Check file size
            if path.stat().st_size > cls.MAX_FILE_SIZE:
                return False, "File size exceeds limit"
            
            return True, str(path)
            
        except Exception as e:
            return False, f"Invalid file path: {e}"
    
    @classmethod
    def validate_pdf(cls, file_path: str) -> tuple[bool, str]:
        """
        Validate PDF file
        
        Args:
            file_path: Path to PDF file
            
        Returns:
            Tuple of (is_valid, error_message or None)
        """
        try:
            import PyPDF2
            
            with open(file_path, 'rb') as f:
                # Try to read the PDF
                reader = PyPDF2.PdfReader(f)
                
                # Check if encrypted
                if reader.is_encrypted:
                    return False, "PDF is encrypted"
                
                # Check page count
                if len(reader.pages) == 0:
                    return False, "PDF has no pages"
                
                if len(reader.pages) > 1000:
                    return False, "PDF has too many pages"
                
                return True, None
                
        except PyPDF2.errors.PdfReadError:
            return False, "Invalid or corrupted PDF"
        except Exception as e:
            return False, f"Error validating PDF: {e}"


class OutputSanitizer:
    """Sanitizes output data before sending to clients"""
    
    @staticmethod
    def sanitize_for_json(data: Any) -> Any:
        """
        Sanitize data for JSON serialization
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data
        """
        import json
        from datetime import datetime, date
        from decimal import Decimal
        
        if isinstance(data, (datetime, date)):
            return data.isoformat()
        elif isinstance(data, Decimal):
            return float(data)
        elif isinstance(data, bytes):
            return data.decode('utf-8', errors='ignore')
        elif isinstance(data, dict):
            return {
                OutputSanitizer.sanitize_for_json(k): OutputSanitizer.sanitize_for_json(v)
                for k, v in data.items()
            }
        elif isinstance(data, (list, tuple)):
            return [OutputSanitizer.sanitize_for_json(item) for item in data]
        elif hasattr(data, '__dict__'):
            return OutputSanitizer.sanitize_for_json(data.__dict__)
        else:
            return data
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """
        Sanitize text for HTML output
        
        Args:
            text: Text to sanitize
            
        Returns:
            HTML-safe text
        """
        import html
        
        # Escape HTML characters
        text = html.escape(text)
        
        # Additional sanitization
        text = text.replace('\x00', '')
        
        return text
    
    @staticmethod
    def redact_sensitive_data(data: Dict, fields_to_redact: List[str] = None) -> Dict:
        """
        Redact sensitive information from data
        
        Args:
            data: Data dictionary
            fields_to_redact: List of field names to redact
            
        Returns:
            Data with sensitive fields redacted
        """
        if fields_to_redact is None:
            fields_to_redact = [
                'password', 'secret', 'token', 'api_key', 
                'private_key', 'ssn', 'credit_card'
            ]
        
        def redact_value(value):
            if isinstance(value, str) and len(value) > 4:
                return value[:2] + '*' * (len(value) - 4) + value[-2:]
            return '****'
        
        def process_dict(d):
            result = {}
            for key, value in d.items():
                if any(sensitive in key.lower() for sensitive in fields_to_redact):
                    result[key] = redact_value(value)
                elif isinstance(value, dict):
                    result[key] = process_dict(value)
                elif isinstance(value, list):
                    result[key] = [
                        process_dict(item) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    result[key] = value
            return result
        
        return process_dict(data)


class RateLimiter:
    """Rate limiting for API requests"""
    
    def __init__(self):
        self.requests = {}
        self.limits = {
            'search': (100, 60),  # 100 requests per 60 seconds
            'process': (10, 60),  # 10 requests per 60 seconds
            'bulk': (5, 60),      # 5 requests per 60 seconds
        }
    
    def check_rate_limit(self, client_id: str, endpoint_type: str = 'search') -> tuple[bool, str]:
        """
        Check if client has exceeded rate limit
        
        Args:
            client_id: Client identifier (IP or user ID)
            endpoint_type: Type of endpoint being accessed
            
        Returns:
            Tuple of (is_allowed, error_message or None)
        """
        from time import time
        
        current_time = time()
        limit, window = self.limits.get(endpoint_type, (100, 60))
        
        # Clean old requests
        self._clean_old_requests(client_id, current_time, window)
        
        # Check current rate
        if client_id not in self.requests:
            self.requests[client_id] = []
        
        if len(self.requests[client_id]) >= limit:
            return False, f"Rate limit exceeded: {limit} requests per {window} seconds"
        
        # Add current request
        self.requests[client_id].append(current_time)
        
        return True, None
    
    def _clean_old_requests(self, client_id: str, current_time: float, window: int):
        """Remove requests older than the time window"""
        if client_id in self.requests:
            cutoff_time = current_time - window
            self.requests[client_id] = [
                t for t in self.requests[client_id] 
                if t > cutoff_time
            ]