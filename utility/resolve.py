import re
import socket
import dns.resolver


def getIP(d):
    """
    This method returns the first IP address string
    that responds as the given domain name
    getHost,getAlias,getIP,getIPx, get_a_record
    """
    try:
        ip = socket.gethostbyname(d)
        ipx = socket.gethostbyname_ex(d)
        return {"result": [ip, ipx[1]]}
    except Exception:
        return {"result": "SocketError: Work with domain input"}


def get_a_record(domain):
    """Return the DNS record information"""
    try:
        _resolver = dns.resolver.Resolver()
        # record_type 'A', 'AAAA', 'NS' 
        rt = 'A'
        result = [val.to_text() for val in _resolver.resolve(domain, rt)]
        return {"result": result}
    except Exception as diag:
        return {"result": diag}


def valid_domain_name(arg: str):
    """Domain Name Validation"""
    regex = re.compile(r'^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$')
    return regex.findall(arg)


def valid_ip_address(arg: str):
    """Ip address validation"""
    regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return regex.findall(arg)
