#!/usr/bin/env python

from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from OpenSSL.SSL import Error as PyOpenSSLError
from OpenSSL.SSL import OP_NO_SSLv3
from OpenSSL.SSL import WantReadError as SSLWantReadError

import json, requests
import argparse

import datetime
import httplib
import os
import re
import signal
import socket
import sys

from time import sleep

HOSTCERT = "/etc/grid-security/hostcert.pem"
HOSTKEY = "/etc/grid-security/hostkey.pem"

MIP_API = '/poem/api/0.2/json/metrics_in_profiles?vo_name=ops'
PR_API = '/poem/api/0.2/json/profiles'

strerr = ''
num_excp_expand = 0
server_expire = None

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

        server_subject = server_cert_chain[-1].get_subject()
        if host != server_subject.CN:
            raise PyOpenSSLError('CN does not match %s' % host)

        global server_expire
        server_expire = server_cert_chain[-1].get_notAfter()

    except PyOpenSSLError as e:
        raise e
    finally:
        server_conn.shutdown()
        server_conn.close()

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', dest='hostname', required=True, type=str, help='hostname')
    parser.add_argument('-r', dest='profile', required=True, type=str, help='profile name')
    parser.add_argument('--capath', dest='capath', required=True, type=str, help='CA directory')
    parser.add_argument('-t', dest='timeout', required=True, type=int, default=180)
    arguments = parser.parse_args()

    # verify server certificate
    try:
        verify_servercert(arguments.hostname, arguments.timeout, arguments.capath)
    except PyOpenSSLError as e:
        print "CRITICAL - Server certificate verification failed: %s" % errmsg_from_excp(e)
        raise SystemExit(2)
    except socket.error as e:
        print "CRITICAL - Connection error: %s" % errmsg_from_excp(e)
        raise SystemExit(2)
    except socket.timeout as e:
        print "CRITICAL - Connection timeout after %s seconds" % args.timeout
        raise SystemExit(2)

    # verify client certificate
    try:
        requests.get('https://' + arguments.hostname + '/poem/', cert=(HOSTCERT, HOSTKEY), verify=False)
    except requests.exceptions.RequestException as e:
        print "CRITICAL - Client certificate verification failed: %s" % errmsg_from_excp(e)
        raise SystemExit(2)

    try:
        metrics = requests.get('https://' + arguments.hostname + MIP_API, cert=(HOSTCERT, HOSTKEY), verify=False)
        metricsjson = metrics.json()
    except requests.exceptions.RequestException as e:
        print 'CRITICAL - cannot connect to %s: %s' % ('https://' + arguments.hostname + MIP_API,
                                                       errmsg_from_excp(e))
        raise SystemExit(2)

    try:
        profiles = requests.get('https://' + arguments.hostname + '/poem/api/0.2/json/profiles', cert=(HOSTCERT, HOSTKEY), verify=False)
        profilesjson = profiles.json()
    except requests.exceptions.RequestException as e:
        print 'CRITICAL - cannot connect to %s: %s' % ('https://' + arguments.hostname + PR_API,
                                                       errmsg_from_excp(e))
        raise SystemExit(2)


    profile, matched_profile = None, None
    try:
        for profile in metricsjson[0]['profiles']:
            if profile['name'] == arguments.profile:
                matched_profile = profile
                break
    except KeyError:
        print 'CRITICAL - cannot retrieve a value from %s' % MIP_API
        raise SystemExit(2)

    if not matched_profile:
        print 'CRITICAL - POEM does not have %s profile' % (arguments.profile)
        raise SystemExit(2)

    servicetypes = set()
    metrics = set()

    try:
        for m in matched_profile['metrics']:
            servicetypes.add(m['name'])
    except KeyError:
        print 'CRITICAL - cannot retrieve a value from %s' % MIP_API
        raise SystemExit(2)

    try:
        for profile in profilesjson:
            if (profile['name'] == arguments.profile):
                for metric in profile['metric_instances']:
                    metrics.add(metric['atp_service_type_flavour'])
                break
    except KeyError:
        print 'CRITICAL - cannot retrieve a value from %s' % PR_API
        raise SystemExit(2)

    global server_expire
    dte = datetime.datetime.strptime(server_expire, '%Y%m%d%H%M%SZ')
    dtn = datetime.datetime.now()
    if (dte - dtn).days <= 15:
        print 'WARNING - Server certificate will expire in %i days' % (dte - dtn).days
        raise SystemExit(1)

    print 'OK - %s has %d distinct service types and %d distinct metrics' % (arguments.profile, len(servicetypes), len(metrics))
    raise SystemExit(0)

if __name__ == "__main__":
    main()
