"""
Indicator Extraction Module for Threat Intelligence Pipeline
Extracts IoCs (Indicators of Compromise) from text with high accuracy
"""

import re
import ipaddress
import tldextract
import phonenumbers
import validators
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from urllib.parse import urlparse, unquote
import logging

logger = logging.getLogger(__name__)


class IndicatorType(Enum):
    """Enumeration of indicator types"""
    DOMAIN = "domain"
    URL = "url"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PHONE = "phone"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    INSTAGRAM = "instagram"
    YOUTUBE = "youtube"
    LINKEDIN = "linkedin"
    TIKTOK = "tiktok"
    TELEGRAM = "telegram"
    REDDIT = "reddit"
    VK = "vk"
    TRUTH_SOCIAL = "truth_social"
    PARLER = "parler"
    GOOGLE_ANALYTICS = "google_analytics"
    ADSENSE = "adsense"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"


@dataclass
class Indicator:
    """Represents an extracted indicator"""
    type: IndicatorType
    value: str
    normalized_value: str
    context: str = ""
    confidence: float = 1.0
    source_position: int = 0
    metadata: Dict = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.type, self.normalized_value))
    
    def __eq__(self, other):
        if not isinstance(other, Indicator):
            return False
        return self.type == other.type and self.normalized_value == other.normalized_value


class IndicatorExtractor:
    """Advanced indicator extraction with normalization and validation"""
    
    def __init__(self, context_window: int = 100):
        self.context_window = context_window
        self.patterns = self._compile_patterns()
        self.whitelist_domains = self._load_whitelist_domains()
        
    def _compile_patterns(self) -> Dict[IndicatorType, re.Pattern]:
        """Compile regex patterns for all indicator types"""
        return {
            IndicatorType.URL: re.compile(
                r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}'
                r'\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
                re.IGNORECASE
            ),
            IndicatorType.DOMAIN: re.compile(
                r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]',
                re.IGNORECASE
            ),
            IndicatorType.IP_ADDRESS: re.compile(
                r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            ),
            IndicatorType.EMAIL: re.compile(
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ),
            IndicatorType.PHONE: re.compile(
                r'[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,5}[-\s\.]?[0-9]{1,5}'
            ),
            IndicatorType.MD5: re.compile(r'\b[a-fA-F0-9]{32}\b'),
            IndicatorType.SHA1: re.compile(r'\b[a-fA-F0-9]{40}\b'),
            IndicatorType.SHA256: re.compile(r'\b[a-fA-F0-9]{64}\b'),
            IndicatorType.FACEBOOK: re.compile(
                r'(?:facebook\.com|fb\.com|fb\.me)/(?:pages/)?(?:[\w\-\.]+/?)?(?:posts/)?[\w\-\./]*',
                re.IGNORECASE
            ),
            IndicatorType.TWITTER: re.compile(
                r'(?:twitter\.com|x\.com)/(?:#!/)?(?:\w+)(?:/status(?:es)?/(\d+))?',
                re.IGNORECASE
            ),
            IndicatorType.INSTAGRAM: re.compile(
                r'(?:instagram\.com|instagr\.am)/(?:p/)?(?:[\w\-\.]+/?)?',
                re.IGNORECASE
            ),
            IndicatorType.YOUTUBE: re.compile(
                r'(?:youtube\.com/(?:watch\?v=|channel/|user/)|youtu\.be/)[\w\-]+',
                re.IGNORECASE
            ),
            IndicatorType.LINKEDIN: re.compile(
                r'linkedin\.com/(?:in|company|pub)/[\w\-\.%]+/?',
                re.IGNORECASE
            ),
            IndicatorType.TIKTOK: re.compile(
                r'tiktok\.com/@[\w\-\.]+(?:/video/\d+)?',
                re.IGNORECASE
            ),
            IndicatorType.TELEGRAM: re.compile(
                r't\.me/(?:joinchat/)?[\w\-]+',
                re.IGNORECASE
            ),
            IndicatorType.REDDIT: re.compile(
                r'reddit\.com/(?:r|u|user)/[\w\-]+(?:/comments/[\w]+)?',
                re.IGNORECASE
            ),
            IndicatorType.VK: re.compile(
                r'vk\.com/(?:id\d+|[\w\-\.]+)',
                re.IGNORECASE
            ),
            IndicatorType.TRUTH_SOCIAL: re.compile(
                r'truthsocial\.com/@[\w\-\.]+',
                re.IGNORECASE
            ),
            IndicatorType.PARLER: re.compile(
                r'parler\.com/(?:profile|post)/[\w\-]+',
                re.IGNORECASE
            ),
            IndicatorType.GOOGLE_ANALYTICS: re.compile(
                r'UA-\d{4,10}-\d{1,4}'
            ),
            IndicatorType.ADSENSE: re.compile(
                r'pub-\d{16}'
            ),
            IndicatorType.BITCOIN: re.compile(
                r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
            ),
            IndicatorType.ETHEREUM: re.compile(
                r'\b0x[a-fA-F0-9]{40}\b'
            ),
        }
    
    def _load_whitelist_domains(self) -> Set[str]:
        """Load domains to exclude from extraction (common legitimate domains)"""
        return {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'cloudflare.com', 'github.com', 'wikipedia.org', 'archive.org',
            'doi.org', 'w3.org', 'schema.org', 'example.com', 'localhost',
            'youtube.com', 'twitter.com', 'facebook.com', 'instagram.com',
            'linkedin.com', 'reddit.com'  # We'll extract these with full paths
        }
    
    def extract_all(self, text: str, source_doc: str = None) -> List[Indicator]:
        """Extract all indicators from text"""
        indicators = []
        
        # Extract URLs first (to avoid double-extraction of domains)
        urls = self._extract_urls(text)
        indicators.extend(urls)
        
        # Extract domains (excluding those already in URLs)
        url_domains = {self._get_domain_from_url(ind.value) for ind in urls}
        domains = self._extract_domains(text, exclude=url_domains)
        indicators.extend(domains)
        
        # Extract IPs
        indicators.extend(self._extract_ips(text))
        
        # Extract emails
        indicators.extend(self._extract_emails(text))
        
        # Extract phone numbers
        indicators.extend(self._extract_phones(text))
        
        # Extract hashes
        indicators.extend(self._extract_hashes(text))
        
        # Extract social media handles
        indicators.extend(self._extract_social_media(text))
        
        # Extract tracking IDs
        indicators.extend(self._extract_tracking_ids(text))
        
        # Extract cryptocurrency addresses
        indicators.extend(self._extract_crypto_addresses(text))
        
        # Add source document to metadata
        if source_doc:
            for ind in indicators:
                ind.metadata['source_document'] = source_doc
        
        return self._deduplicate_indicators(indicators)
    
    def _extract_urls(self, text: str) -> List[Indicator]:
        """Extract and validate URLs"""
        indicators = []
        pattern = self.patterns[IndicatorType.URL]
        
        for match in pattern.finditer(text):
            url = match.group()
            normalized = self._normalize_url(url)
            
            if self._validate_url(normalized):
                context = self._extract_context(text, match.start(), match.end())
                indicators.append(Indicator(
                    type=IndicatorType.URL,
                    value=url,
                    normalized_value=normalized,
                    context=context,
                    source_position=match.start(),
                    confidence=0.95
                ))
        
        return indicators
    
    def _extract_domains(self, text: str, exclude: Set[str] = None) -> List[Indicator]:
        """Extract and validate domains"""
        indicators = []
        pattern = self.patterns[IndicatorType.DOMAIN]
        exclude = exclude or set()
        
        for match in pattern.finditer(text):
            domain = match.group().lower()
            
            # Skip if in exclude list or whitelist
            if domain in exclude or domain in self.whitelist_domains:
                continue
            
            # Validate domain
            if self._validate_domain(domain):
                context = self._extract_context(text, match.start(), match.end())
                indicators.append(Indicator(
                    type=IndicatorType.DOMAIN,
                    value=match.group(),
                    normalized_value=domain,
                    context=context,
                    source_position=match.start(),
                    confidence=0.9
                ))
        
        return indicators
    
    def _extract_ips(self, text: str) -> List[Indicator]:
        """Extract and validate IP addresses"""
        indicators = []
        pattern = self.patterns[IndicatorType.IP_ADDRESS]
        
        for match in pattern.finditer(text):
            ip = match.group()
            
            try:
                # Validate IP address
                ip_obj = ipaddress.ip_address(ip)
                
                # Skip private/reserved IPs unless explicitly needed
                if not ip_obj.is_private and not ip_obj.is_reserved:
                    context = self._extract_context(text, match.start(), match.end())
                    indicators.append(Indicator(
                        type=IndicatorType.IP_ADDRESS,
                        value=ip,
                        normalized_value=str(ip_obj),
                        context=context,
                        source_position=match.start(),
                        metadata={'ip_version': ip_obj.version}
                    ))
            except ValueError:
                continue
        
        return indicators
    
    def _extract_emails(self, text: str) -> List[Indicator]:
        """Extract and validate email addresses"""
        indicators = []
        pattern = self.patterns[IndicatorType.EMAIL]
        
        for match in pattern.finditer(text):
            email = match.group().lower()
            
            if validators.email(email):
                context = self._extract_context(text, match.start(), match.end())
                domain = email.split('@')[1]
                indicators.append(Indicator(
                    type=IndicatorType.EMAIL,
                    value=match.group(),
                    normalized_value=email,
                    context=context,
                    source_position=match.start(),
                    metadata={'domain': domain}
                ))
        
        return indicators
    
    def _extract_phones(self, text: str) -> List[Indicator]:
        """Extract and validate phone numbers"""
        indicators = []
        pattern = self.patterns[IndicatorType.PHONE]
        
        for match in pattern.finditer(text):
            phone = match.group()
            
            try:
                # Try to parse with phonenumbers library
                parsed = phonenumbers.parse(phone, None)
                if phonenumbers.is_valid_number(parsed):
                    normalized = phonenumbers.format_number(
                        parsed, 
                        phonenumbers.PhoneNumberFormat.E164
                    )
                    context = self._extract_context(text, match.start(), match.end())
                    indicators.append(Indicator(
                        type=IndicatorType.PHONE,
                        value=phone,
                        normalized_value=normalized,
                        context=context,
                        source_position=match.start(),
                        metadata={
                            'country_code': parsed.country_code,
                            'national_number': parsed.national_number
                        }
                    ))
            except:
                # If parsing fails, still include if it matches pattern
                if len(re.sub(r'\D', '', phone)) >= 7:
                    context = self._extract_context(text, match.start(), match.end())
                    indicators.append(Indicator(
                        type=IndicatorType.PHONE,
                        value=phone,
                        normalized_value=re.sub(r'\D', '', phone),
                        context=context,
                        source_position=match.start(),
                        confidence=0.7
                    ))
        
        return indicators
    
    def _extract_hashes(self, text: str) -> List[Indicator]:
        """Extract file hashes (MD5, SHA1, SHA256)"""
        indicators = []
        
        for hash_type in [IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256]:
            pattern = self.patterns[hash_type]
            
            for match in pattern.finditer(text):
                hash_value = match.group().lower()
                
                # Basic validation - check if it's not all the same character
                if len(set(hash_value)) > 1:
                    context = self._extract_context(text, match.start(), match.end())
                    indicators.append(Indicator(
                        type=hash_type,
                        value=match.group(),
                        normalized_value=hash_value,
                        context=context,
                        source_position=match.start()
                    ))
        
        return indicators
    
    def _extract_social_media(self, text: str) -> List[Indicator]:
        """Extract social media handles and profiles"""
        indicators = []
        
        social_types = [
            IndicatorType.FACEBOOK, IndicatorType.TWITTER, IndicatorType.INSTAGRAM,
            IndicatorType.YOUTUBE, IndicatorType.LINKEDIN, IndicatorType.TIKTOK,
            IndicatorType.TELEGRAM, IndicatorType.REDDIT, IndicatorType.VK,
            IndicatorType.TRUTH_SOCIAL, IndicatorType.PARLER
        ]
        
        for social_type in social_types:
            pattern = self.patterns[social_type]
            
            for match in pattern.finditer(text):
                handle = match.group()
                normalized = self._normalize_social_handle(handle, social_type)
                
                context = self._extract_context(text, match.start(), match.end())
                indicators.append(Indicator(
                    type=social_type,
                    value=handle,
                    normalized_value=normalized,
                    context=context,
                    source_position=match.start(),
                    metadata={'platform': social_type.value}
                ))
        
        return indicators
    
    def _extract_tracking_ids(self, text: str) -> List[Indicator]:
        """Extract Google Analytics and AdSense IDs"""
        indicators = []
        
        for tracking_type in [IndicatorType.GOOGLE_ANALYTICS, IndicatorType.ADSENSE]:
            pattern = self.patterns[tracking_type]
            
            for match in pattern.finditer(text):
                tracking_id = match.group()
                context = self._extract_context(text, match.start(), match.end())
                indicators.append(Indicator(
                    type=tracking_type,
                    value=tracking_id,
                    normalized_value=tracking_id,
                    context=context,
                    source_position=match.start()
                ))
        
        return indicators
    
    def _extract_crypto_addresses(self, text: str) -> List[Indicator]:
        """Extract cryptocurrency addresses"""
        indicators = []
        
        for crypto_type in [IndicatorType.BITCOIN, IndicatorType.ETHEREUM]:
            pattern = self.patterns[crypto_type]
            
            for match in pattern.finditer(text):
                address = match.group()
                context = self._extract_context(text, match.start(), match.end())
                indicators.append(Indicator(
                    type=crypto_type,
                    value=address,
                    normalized_value=address,
                    context=context,
                    source_position=match.start(),
                    metadata={'cryptocurrency': crypto_type.value}
                ))
        
        return indicators
    
    def _extract_context(self, text: str, start: int, end: int) -> str:
        """Extract context around an indicator"""
        context_start = max(0, start - self.context_window)
        context_end = min(len(text), end + self.context_window)
        
        context = text[context_start:context_end]
        
        # Clean up context
        context = ' '.join(context.split())
        
        # Add ellipsis if truncated
        if context_start > 0:
            context = '...' + context
        if context_end < len(text):
            context = context + '...'
        
        return context
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for comparison"""
        url = url.lower()
        url = unquote(url)  # Decode URL encoding
        
        # Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]
        
        return url
    
    def _normalize_social_handle(self, handle: str, platform: IndicatorType) -> str:
        """Normalize social media handles"""
        handle = handle.lower()
        
        # Extract just the username for certain platforms
        if platform == IndicatorType.TWITTER:
            if '@' in handle:
                handle = handle.split('@')[1]
        elif platform == IndicatorType.TELEGRAM:
            if 't.me/' in handle:
                handle = handle.split('t.me/')[1].split('/')[0]
        
        return handle
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL structure"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain structure"""
        if len(domain) > 253:
            return False
        
        # Check for valid TLD
        extracted = tldextract.extract(domain)
        if not extracted.suffix:
            return False
        
        # Check for common false positives
        if domain.count('.') > 10:  # Too many subdomains
            return False
        
        return True
    
    def _get_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _deduplicate_indicators(self, indicators: List[Indicator]) -> List[Indicator]:
        """Remove duplicate indicators, keeping the one with highest confidence"""
        unique = {}
        
        for ind in indicators:
            key = (ind.type, ind.normalized_value)
            if key not in unique or ind.confidence > unique[key].confidence:
                unique[key] = ind
        
        return list(unique.values())
    
    def get_statistics(self, indicators: List[Indicator]) -> Dict:
        """Generate statistics about extracted indicators"""
        stats = {
            'total': len(indicators),
            'by_type': {},
            'confidence_distribution': {
                'high': 0,  # >= 0.9
                'medium': 0,  # >= 0.7
                'low': 0  # < 0.7
            }
        }
        
        for ind in indicators:
            # Count by type
            type_name = ind.type.value
            stats['by_type'][type_name] = stats['by_type'].get(type_name, 0) + 1
            
            # Count by confidence
            if ind.confidence >= 0.9:
                stats['confidence_distribution']['high'] += 1
            elif ind.confidence >= 0.7:
                stats['confidence_distribution']['medium'] += 1
            else:
                stats['confidence_distribution']['low'] += 1
        
        return stats