"""HTTP probing and technology detection."""

import re
import socket
import time
import warnings
from typing import Optional

import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings - we're intentionally ignoring cert issues
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

from dotmil_recon.core.models import HttpProbeResult


# Technology fingerprints: header -> pattern -> tech name
HEADER_FINGERPRINTS: dict[str, list[tuple[str, str]]] = {
    "server": [
        (r"apache", "Apache"),
        (r"nginx", "Nginx"),
        (r"microsoft-iis/(\d+\.?\d*)", "IIS/{0}"),
        (r"cloudflare", "Cloudflare"),
        (r"akamai", "Akamai"),
        (r"tomcat", "Apache Tomcat"),
        (r"jetty", "Jetty"),
        (r"lighttpd", "Lighttpd"),
        (r"openresty", "OpenResty"),
        (r"gunicorn", "Gunicorn"),
        (r"werkzeug", "Werkzeug"),
    ],
    "x-powered-by": [
        (r"php/?([\d.]*)", "PHP/{0}"),
        (r"asp\.?net", "ASP.NET"),
        (r"express", "Express.js"),
        (r"servlet", "Java Servlet"),
        (r"jsp", "JSP"),
        (r"coldfusion", "ColdFusion"),
        (r"perl", "Perl"),
        (r"python", "Python"),
        (r"ruby", "Ruby"),
        (r"next\.js", "Next.js"),
    ],
    "x-aspnet-version": [
        (r"([\d.]+)", "ASP.NET/{0}"),
    ],
    "x-aspnetmvc-version": [
        (r"([\d.]+)", "ASP.NET MVC/{0}"),
    ],
    "x-generator": [
        (r"drupal", "Drupal"),
        (r"wordpress", "WordPress"),
        (r"joomla", "Joomla"),
    ],
    "x-drupal-cache": [
        (r".*", "Drupal"),
    ],
    "x-varnish": [
        (r".*", "Varnish"),
    ],
    "x-cache": [
        (r".*", "CDN/Cache"),
    ],
    "via": [
        (r"varnish", "Varnish"),
        (r"cloudfront", "CloudFront"),
        (r"squid", "Squid"),
    ],
}

# Body patterns for tech detection
BODY_FINGERPRINTS: list[tuple[str, str]] = [
    (r"<meta[^>]+generator[^>]+wordpress", "WordPress"),
    (r"<meta[^>]+generator[^>]+drupal", "Drupal"),
    (r"<meta[^>]+generator[^>]+joomla", "Joomla"),
    (r"wp-content/", "WordPress"),
    (r"sites/default/files", "Drupal"),
    (r"SharePoint", "SharePoint"),
    (r"/_layouts/", "SharePoint"),
    (r"Confluence", "Confluence"),
    (r"JSESSIONID", "Java"),
    (r"__VIEWSTATE", "ASP.NET"),
    (r"csrftoken.*django", "Django"),
    (r"laravel_session", "Laravel"),
    (r"ci_session", "CodeIgniter"),
]

# Interesting headers to always capture
INTERESTING_HEADERS: list[str] = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-varnish",
    "x-cache",
    "via",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options",
    "content-security-policy",
    "strict-transport-security",
    "www-authenticate",
    "set-cookie",
]


def _extract_title(body: str) -> Optional[str]:
    """Extract page title from HTML body."""
    match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    if match:
        return match.group(1).strip()[:200]
    return None


def _detect_technologies(headers: dict[str, str], body: str) -> list[str]:
    """Detect technologies from headers and body content."""
    technologies: set[str] = set()
    
    # Header-based detection
    for header_name, patterns in HEADER_FINGERPRINTS.items():
        header_value = headers.get(header_name, "").lower()
        if not header_value:
            continue
        
        for pattern, tech_name in patterns:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                # Handle version capture groups
                if "{0}" in tech_name and match.groups():
                    tech_name = tech_name.format(match.group(1))
                elif "{0}" in tech_name:
                    tech_name = tech_name.replace("/{0}", "")
                technologies.add(tech_name)
    
    # Cookie-based detection
    cookies = headers.get("set-cookie", "").lower()
    if "phpsessid" in cookies:
        technologies.add("PHP")
    if "jsessionid" in cookies:
        technologies.add("Java")
    if "asp.net" in cookies or "aspxauth" in cookies:
        technologies.add("ASP.NET")
    if "laravel" in cookies:
        technologies.add("Laravel")
    
    # Body-based detection (only first 50KB)
    body_sample = body[:50000].lower()
    for pattern, tech_name in BODY_FINGERPRINTS:
        if re.search(pattern, body_sample, re.IGNORECASE):
            technologies.add(tech_name)
    
    return sorted(technologies)


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    """Keep only interesting headers."""
    return {
        k: v for k, v in headers.items() 
        if k.lower() in INTERESTING_HEADERS
    }


def probe_url(url: str, timeout: float = 30.0, follow_redirects: bool = True) -> Optional[HttpProbeResult]:
    """
    Probe a single URL and collect information.
    
    Args:
        url: Full URL to probe (http:// or https://)
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
        
    Returns:
        HttpProbeResult or None if probe failed
    """
    start_time = time.time()
    
    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=follow_redirects,
            verify=False,  # Don't fail on cert issues
            headers={"User-Agent": "dotmil-recon/0.1.0"},
            stream=True,  # Don't load full body immediately
        )
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Read limited body for fingerprinting
        body = ""
        try:
            body = response.text[:100000]
        except Exception:
            pass
        
        # Normalize headers to lowercase keys
        headers = {k.lower(): v for k, v in response.headers.items()}
        filtered_headers = _filter_headers(headers)
        
        # Detect technologies
        technologies = _detect_technologies(headers, body)
        
        # Determine final URL after redirects
        final_url: Optional[str] = None
        if response.url != url:
            final_url = response.url
        
        return HttpProbeResult(
            url=url,
            status_code=response.status_code,
            final_url=final_url,
            headers=filtered_headers,
            technologies=technologies,
            server=headers.get("server"),
            title=_extract_title(body),
            content_length=int(headers.get("content-length", 0)) or None,
            tls=url.startswith("https://"),
            duration_ms=duration_ms,
        )
        
    except requests.exceptions.Timeout:
        return HttpProbeResult(
            url=url,
            status_code=0,
            tls=url.startswith("https://"),
            error="timeout",
            duration_ms=int((time.time() - start_time) * 1000),
        )
    except requests.exceptions.ConnectionError as e:
        error_msg = "connection_refused"
        if "Name or service not known" in str(e):
            error_msg = "dns_failed"
        elif "Connection refused" in str(e):
            error_msg = "connection_refused"
        elif "Network is unreachable" in str(e):
            error_msg = "network_unreachable"
        return HttpProbeResult(
            url=url,
            status_code=0,
            tls=url.startswith("https://"),
            error=error_msg,
            duration_ms=int((time.time() - start_time) * 1000),
        )
    except requests.exceptions.SSLError as e:
        return HttpProbeResult(
            url=url,
            status_code=0,
            tls=url.startswith("https://"),
            error=f"ssl_error: {str(e)[:100]}",
            duration_ms=int((time.time() - start_time) * 1000),
        )
    except Exception as e:
        return HttpProbeResult(
            url=url,
            status_code=0,
            tls=url.startswith("https://"),
            error=f"unknown: {str(e)[:100]}",
            duration_ms=int((time.time() - start_time) * 1000),
        )


def probe_domain(domain: str, timeout: float = 30.0) -> tuple[Optional[HttpProbeResult], Optional[HttpProbeResult]]:
    """
    Probe both HTTP and HTTPS for a domain.
    
    Args:
        domain: Domain name to probe
        timeout: Request timeout in seconds
        
    Returns:
        Tuple of (http_result, https_result), either may be None
    """
    http_result = probe_url(f"http://{domain}", timeout=timeout)
    https_result = probe_url(f"https://{domain}", timeout=timeout)
    
    return http_result, https_result


def resolve_ip(domain: str, timeout: float = 60.0) -> Optional[str]:
    """Resolve domain to IP address."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyname(domain)
    except socket.error:
        return None
