

class Error(Exception):
    """Base class for exceptions"""
    pass


class VirusTotalApiError(Error):
    """
    Custom-defined exception for error messages returned by the API.
    
    Example:
        >>> try:
        ...     print(vt_ip.info_ip('8.8.8.x'))
        ... except virustotal3.errors.VirusTotalApiError as e:
        ...     print(e)
        ...     exit()
    """
    def __init__(self, message):
        self.message = message

class UrlScanApiError(Error):
    """
    Custom-defined exception for error messages returned by the API.
    
    Example:
        >>> try:
        ...     print(vt_ip.info_ip('8.8.8.x'))
        ... except virustotal3.errors.VirusTotalApiError as e:
        ...     print(e)
        ...     exit()
    """
    def __init__(self, message):
        self.message = message

def raise_exception(response):
    """Raise Exception"""
    # https://developers.virustotal.com/v3.0/reference#errors
    raise VirusTotalApiError(response.text)

def _raise_exception(response):
    """Raise Exception"""
    # https://urlscan.io/docs/api/#errors
    raise UrlScanApiError(response.text)
