HOSTCERT = "/etc/grid-security/hostcert.pem"
HOSTKEY = "/etc/grid-security/hostkey.pem"
CAPATH = "/etc/grid-security/certificates/"

MIP_API = '/api/v2/metrics'
TENANT_API = '/api/v2/internal/public_tenants/'
METRICS_API = '/api/v2/internal/public_metric/'

SUPERPOEM = 'SuperPOEM Tenant'

strerr = '' # Error message string
num_excp_expand = 0
server_expire = None
# Prints a message from exception
def errmsg_from_excp(e):
    global strerr, num_excp_expand
    if isinstance(e, Exception) and getattr(e, 'args', False):
        num_excp_expand += 1
        if not errmsg_from_excp(e.args):
            return strerr
    elif isinstance(e, dict):
        for s in e.iteritems():
            errmsg_from_excp(s)
    elif isinstance(e, list):
        for s in e:
            errmsg_from_excp(s)
    elif isinstance(e, tuple):
        for s in e:
            errmsg_from_excp(s)
    elif isinstance(e, str):
        if num_excp_expand <= 5:
            strerr += e + ' '
    elif isinstance(e, int):
        if num_excp_expand <= 5:
            strerr += str(e) + ' '

# Removes element with name=name from json and returns updated json
# If element doesn't exist the original json is returned
def removeNameFromJSON(json, name):
    for element in json:
        if element['name'] == name:
            el_for_removal = element
            break
    if el_for_removal != None:
        json.remove(el_for_removal)
    return json
