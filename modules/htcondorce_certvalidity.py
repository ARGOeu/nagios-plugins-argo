import argparse
import datetime
import os
import re
import sys

import OpenSSL
import htcondor
import pytz
from dateutil.parser import parse

from NagiosResponse import NagiosResponse
from refresh_token_expiration import timeout

nagios = NagiosResponse()


def validate_certificate(args):
    # Setting X509_USER_PROXY environmental variable
    os.environ["X509_USER_PROXY"] = args.user_proxy

    try:
        ad = htcondor.Collector("%s:9619" % args.hostname).locate(
            htcondor.DaemonTypes.Schedd, args.hostname
        )
        cert = htcondor.SecMan().ping(ad, "READ")["ServerPublicCert"]
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert
        )
        expiration_date = parse(x509.get_notAfter())

        subject = x509.get_subject()
        cn = subject.CN
        pattern = re.compile(cn.replace('*', '[A-Za-z0-9_-]+?'))
        cn_ok = False
        if bool(re.match(pattern, args.hostname)):
            cn_ok = True

        else:
            ext_count = x509.get_extension_count()
            san = ''
            for i in range(ext_count):
                ext = x509.get_extension(i)
                if 'subjectAltName' in str(ext.get_short_name()):
                    san = ext.__str__()

            if san:
                for alt_name in san:
                    pattern = re.compile(
                        alt_name.replace('*', '[A-Za-z0-9_-]+?')
                    )
                    if bool(re.match(pattern, args.hostname)):
                        cn_ok = True
                        break

        if cn_ok:
            if x509.has_expired():
                nagios.writeCriticalMessage(
                    "HTCondorCE certificate expired (was valid until %s)!" %
                    expiration_date.strftime('%b %-d %H:%M:%S %Y %Z')
                )
                nagios.setCode(nagios.CRITICAL)

            else:
                timedelta = expiration_date - datetime.datetime.now(tz=pytz.utc)

                if timedelta.days < 30:
                    nagios.writeWarningMessage(
                        "HTCondorCE certificate will expire in "
                        "%d day(s) on %s!" % (
                            timedelta.days,
                            expiration_date.strftime('%b %-d %H:%M:%S %Y %Z')
                        )
                    )
                    nagios.setCode(nagios.WARNING)

                else:
                    nagios.writeOkMessage(
                        "HTCondorCE certificate valid until %s "
                        "(expires in %d days)" % (
                            expiration_date.strftime('%b %-d %H:%M:%S %Y %Z'),
                            timedelta.days
                        )
                    )
                    nagios.setCode(nagios.OK)

        else:
            nagios.writeCriticalMessage(
                'invalid CN (%s does not match %s)' % (args.hostname, cn)
            )
            nagios.setCode(nagios.CRITICAL)

        print nagios.getMsg()

    except htcondor.HTCondorException as e:
        print "UNKNOWN - Unable to fetch certificate: %s" % str(e)
        nagios.setCode(nagios.UNKNOWN)

    except Exception as e:
        print 'UNKNOWN - %s' % str(e)
        nagios.setCode(nagios.UNKNOWN)

    sys.exit(nagios.getCode())


def main():
    parser = argparse.ArgumentParser(
        description="Nagios probe for checking HTCondorCE certificate validity"
    )
    parser.add_argument(
        "--user_proxy", dest="user_proxy", type=str, required=True,
        help="path to X509 user proxy"
    )
    parser.add_argument(
        "-H", "--hostname", dest="hostname", type=str, required=True,
        help="hostname"
    )
    parser.add_argument(
        "-t", "--timeout", dest="timeout", type=int, default=60, help="timeout"
    )
    args = parser.parse_args()

    with timeout(seconds=args.timeout):
        validate_certificate(args)


if __name__ == "__main__":
    main()
