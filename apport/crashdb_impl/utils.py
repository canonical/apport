import os
try:
    from launchpadlib.credentials import Credentials
    from launchpadlib.launchpad import Launchpad, STAGING_SERVICE_ROOT
    from launchpadlib.errors import HTTPError
except ImportError:
    Credentials = None
    Launchpad = None
    

def find_credentials(consumer, files, level=None):
    """ search for credentials matching 'consumer' in path for given access level. """
    if Credentials is None:
        raise ImportError("please install python-launchpadlib")
        
    for f in files:
        cred = Credentials()
        try:
            cred.load(open(f))
        except:
            continue
        if cred.consumer.key == consumer:
            return cred        
    raise IOError("No credentials found")
    
def get_credentials(consumer, cred_file=None, level=None):
    files = list()
    if cred_file:
        files.append(cred_file)
    if "LPCREDENTIALS" in os.environ:
        files.append(os.environ["LPCREDENTIALS"])
    files.extend([
        os.path.join(os.getcwd(), "lp_credentials.txt"),
        os.path.expanduser("~/lp_credentials.txt"),
    ])
    return find_credentials(consumer, files, level)
    
def get_launchpad(consumer, server=STAGING_SERVICE_ROOT, cache=None,
                  cred_file=None, level=None):
    if Launchpad is None:
        raise ImportError("please install python-launchpadlib")
        
    credentials = get_credentials(consumer, cred_file, level)
    cache = cache or os.environ.get("LPCACHE", None)
    return Launchpad(credentials, server, cache)
