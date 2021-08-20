#!/usr/bin/env python
import requests
import argparse

from time import sleep

DEF_MAN_METRICS = ['argo.AMSPublisher-Check', # Default mandatory metrics
'argo.OIDC.CheckRefreshTokenValidity', 
'argo.OIDC.RefreshToken',
'hr.srce.CertLifetime-Local',
'org.nagios.AmsDirSize',
'org.nagios.DiskCheck-Local',
'org.nagios.NagiosCmdFile',
'org.nagios.ProcessCrond']

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


def main():
    critical = [] # Lists for messages
    warning = []
    unknown = []

    parser = argparse.ArgumentParser()
    parser.add_argument('--mandatory-metrics', dest='manmetrics', default=DEF_MAN_METRICS,
     type=str, nargs='*', help='List of mandatory metrics seperated by space')
    arguments = parser.parse_args()
    try:
        tenants = requests.get('https://poem.argo.grnet.gr/' + TENANT_API).json()
        tenants = removeNameFromJSON(tenants, SUPERPOEM)
        for tenant in tenants:
            #print("Currently checking : " + tenant['name'])
            
            # Check mandatory metrics
            try:
                metrics = requests.get('https://' + tenant['domain_url'] + METRICS_API).json()

                missing_metrics = arguments.manmetrics.copy()
                for metric in metrics:
                    if metric['name'] in arguments.manmetrics:
                        missing_metrics.remove(metric['name'])

                for metric in missing_metrics:
                    critical.append('Customer: ' + tenant['name'] + ' - Metric %s is missing!' % metric)
                    #raise SystemExit(2)

            except requests.exceptions.RequestException as e:
                critical.append('Customer: ' + tenant['name'] + ' - cannot connect to %s: %s' % ('https://' + tenant['domain_url'] + METRICS_API,
                                                            errmsg_from_excp(e)))
                #raise SystemExit(2)
            except ValueError as e:
                critical.append('Customer: ' + tenant['name'] + ' - %s - %s' % (METRICS_API, errmsg_from_excp(e)))
                #raise SystemExit(2)

        printMessages(warning, critical, unknown)
        raise SystemExit(0)




    except requests.exceptions.RequestException as e:
        print('CRITICAL - cannot connect to %s: %s' % ('https://' + tenant['name'] + TENANT_API,
                                                    errmsg_from_excp(e)))
        #raise SystemExit(2)
    except ValueError as e:
        print('CRITICAL - %s - %s' % (TENANT_API, errmsg_from_excp(e)))
        #raise SystemExit(2)

if __name__ == "__main__":
    main()