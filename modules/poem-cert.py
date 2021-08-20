#!/usr/bin/env python

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from OpenSSL.SSL import VERIFY_PEER
from OpenSSL.SSL import Error as PyOpenSSLError
from OpenSSL.SSL import WantReadError as SSLWantReadError

import requests
import argparse

import datetime
import socket

from time import sleep

HOSTCERT = "/etc/grid-security/hostcert.pem"
HOSTKEY = "/etc/grid-security/hostkey.pem"
CAPATH = "/etc/grid-security/certificates/"

MIP_API = '/api/v2/metrics'
TENANT_API = '/api/v2/internal/public_tenants/'
METRICS_API = '/api/v2/internal/public_metric/'

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

# Verifies server certificate
def verify_servercert(host, timeout, capath):
    server_ctx = Context(TLSv1_METHOD)
    server_ctx.load_verify_locations(None, capath)
    server_cert_chain = []

    def verify_cb(conn, cert, errnum, depth, ok):
        server_cert_chain.append(cert)
        return ok
    server_ctx.set_verify(VERIFY_PEER, verify_cb)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(1)
    sock.settimeout(timeout)
    sock.connect((host, 443))

    server_conn = Connection(server_ctx, sock)
    server_conn.set_connect_state()

    def iosock_try():
        ok = True
        try:
            server_conn.do_handshake()
            sleep(0.5)
        except SSLWantReadError as e:
            ok = False
            pass
        except Exception as e:
            raise e
        return ok

    try:
        while True:
            if iosock_try():
                break

        global server_expire
        server_expire = server_cert_chain[-1].get_notAfter()

    except PyOpenSSLError as e:
        raise e
    finally:
        server_conn.shutdown()
        server_conn.close()

    return True

def printMessages(warning, critical, unknown):
    def printHelp(list, tag):
        if len(list) > 0:
            print(tag + ' - ', end="")
            i = 0
            for note in list:
                print(note, end = "")
                if(i < len(list) - 1):
                    print(" / ", end='')
                else:
                    print()
                i += 1
            return False
        return True
    ok = True
    if not printHelp(warning, 'Warning'):
        ok = False
    if not printHelp(critical, 'Critical'):
        ok = False
    if printHelp(unknown, 'Unknown'):
        ok = False
    if ok:
        print('OK')


def main():
    critical = [] # Lists for messages
    warning = []
    unknown = []

    parser = argparse.ArgumentParser()
    #parser.add_argument('-r', dest='profile', required=True, type=str, help='profile name')
    parser.add_argument('--cert', dest='cert', default=HOSTCERT, type=str, help='Certificate')
    parser.add_argument('--key', dest='key', default=HOSTKEY, type=str, help='Certificate key')
    parser.add_argument('--capath', dest='capath', default=CAPATH, type=str, help='CA directory')
    #parser.add_argument('--token', dest='token', required=True, type=str, help='API token')
    parser.add_argument('-t', dest='timeout', type=int, default=180)
    arguments = parser.parse_args()
    try:
        tenants = requests.get('https://poem.argo.grnet.gr/' + TENANT_API).json()
        for tenant in tenants:
            #print("Currently checking : " + tenant['name'])

            # verify server certificate
            try:
                verify_servercert(tenant['domain_url'], arguments.timeout, arguments.capath)
            except PyOpenSSLError as e:
                critical.append('Customer: ' + tenant['name'] + ' - Server certificate verification failed: %s' % errmsg_from_excp(e))
                #raise SystemExit(2)
            except socket.error as e:
                critical.append('Customer: ' + tenant['name'] + ' - Connection error: %s' % errmsg_from_excp(e))
                #raise SystemExit(2)
            except socket.timeout as e:
                critical.append('Customer: ' + tenant['name'] + ' - Connection timeout after %s seconds' % arguments.timeout)
                #raise SystemExit(2)


            # verify client certificate
            try:
                requests.get('https://' + tenant['domain_url'] + '/poem/', cert=(arguments.cert, arguments.key), verify=True)
            except requests.exceptions.RequestException as e:
                critical.append('Customer: ' + tenant['name'] + ' - Client certificate verification failed: %s' % errmsg_from_excp(e))
                #raise SystemExit(2)


            # Check certificate expire date
            global server_expire
            dte = datetime.datetime.strptime(server_expire.decode('utf-8'), '%Y%m%d%H%M%SZ')
            dtn = datetime.datetime.now()
            if (dte - dtn).days <= 15:
                warning.append('Customer: ' + tenant['name'] + ' - Server certificate will expire in %i days' % (dte - dtn).days)
                #raise SystemExit(1)

        printMessages(warning, critical, unknown)
        raise SystemExit(0)


    except requests.exceptions.RequestException as e:
        print('CRITICAL - cannot connect to %s: %s' % ('https://' + tenant['name'] + MIP_API,
                                                    errmsg_from_excp(e)))
        #raise SystemExit(2)
    except ValueError as e:
        print('CRITICAL - %s - %s' % (MIP_API, errmsg_from_excp(e)))
        #raise SystemExit(2)

if __name__ == "__main__":
    main()