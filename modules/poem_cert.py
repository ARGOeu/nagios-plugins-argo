from OpenSSL.SSL import TLSv1_METHOD, Context, Connection
from OpenSSL.SSL import VERIFY_PEER
from OpenSSL.SSL import Error as PyOpenSSLError
from OpenSSL.SSL import WantReadError as SSLWantReadError

from NagiosResponse import NagiosResponse

import requests
import argparse

import datetime
import socket

import utils
from utils import errmsg_from_excp

from time import sleep

HOSTCERT = "/etc/grid-security/hostcert.pem"
HOSTKEY = "/etc/grid-security/hostkey.pem"
CAPATH = "/etc/grid-security/certificates/"

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


        global server_subject
        server_subject = server_cert_chain[-1].get_subject()

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
    parser.add_argument('--cert', dest='cert', default=HOSTCERT, type=str, help='Certificate')
    parser.add_argument('--key', dest='key', default=HOSTKEY, type=str, help='Certificate key')
    parser.add_argument('--capath', dest='capath', default=CAPATH, type=str, help='CA directory')
    parser.add_argument('-t', dest='timeout', type=int, default=180)
    arguments = parser.parse_args()

    nagios_response = NagiosResponse("All certificates are valid!")

    try:
        tenants = requests.get('https://' + utils.MAIN_ADDRESS + utils.TENANT_API).json()
        tenants = utils.remove_name_from_json(tenants, utils.SUPERPOEM)

        for tenant in tenants:
            #print("Currently checking : " + tenant['name']) # HELP PRINT

            # verify server certificate
            try:
                verify_servercert(tenant['domain_url'], arguments.timeout, arguments.capath)
            except PyOpenSSLError as e:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - Server certificate verification failed: %s' % errmsg_from_excp(e))
            except socket.error as e:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - Connection error: %s' % errmsg_from_excp(e))
            except socket.timeout as e:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - Connection timeout after %s seconds' % arguments.timeout)
            except Exception:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('CRITICAL - %s' % (errmsg_from_excp(e)))


            # verify client certificate
            try:
                requests.get('https://' + tenant['domain_url'] + '/poem/', cert=(arguments.cert, arguments.key), verify=True)
            except requests.exceptions.RequestException as e:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - Client certificate verification failed: %s' % errmsg_from_excp(e))
            except Exception:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('CRITICAL - %s' % (errmsg_from_excp(e)))

            # Check if certificate CN matches host name
            global server_subject
            if server_subject.CN != tenant['domain_url']:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Server certificate CN does not match %s' % tenant['domain_url'])

            # Check certificate expire date
            global server_expire
            dte = datetime.datetime.strptime(server_expire.decode('utf-8'), '%Y%m%d%H%M%SZ')
            dtn = datetime.datetime.now()
            if (dte - dtn).days <= 15:
                nagios_response.setCode(NagiosResponse.WARNING)
                nagios_response.writeWarningMessage('Customer: ' + tenant['name'] + ' - Server certificate will expire in %i days' % (dte - dtn).days)

    except requests.exceptions.RequestException as e:
        nagios_response.setCode(NagiosResponse.CRITICAL)
        nagios_response.writeCriticalMessage('CRITICAL - cannot connect to %s: %s' % ('https://' + utils.MAIN_ADDRESS + utils.TENANT_API,
                                                    errmsg_from_excp(e)))

    except ValueError as e:
        nagios_response.setCode(NagiosResponse.CRITICAL)
        nagios_response.writeCriticalMessage('CRITICAL - %s - %s' % (utils.TENANT_API, errmsg_from_excp(e)))

    except Exception:
        nagios_response.setCode(NagiosResponse.CRITICAL)
        nagios_response.writeCriticalMessage('CRITICAL - %s' % (errmsg_from_excp(e)))

    print(nagios_response.getMsg())
    raise SystemExit(nagios_response.getCode())

if __name__ == "__main__":
    main()