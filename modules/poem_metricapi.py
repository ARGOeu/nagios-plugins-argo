import requests
import argparse

from NagiosResponse import NagiosResponse

import utils
from utils import errmsg_from_excp

DEF_MAN_METRICS = ['argo.AMSPublisher-Check', # Default mandatory metrics
'argo.OIDC.CheckRefreshTokenValidity', 
'argo.OIDC.RefreshToken',
'hr.srce.CertLifetime-Local',
'org.nagios.AmsDirSize',
'org.nagios.DiskCheck-Local',
'org.nagios.NagiosCmdFile',
'org.nagios.ProcessCrond']

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mandatory-metrics', dest='manmetrics', default=DEF_MAN_METRICS,
     type=str, nargs='*', help='List of mandatory metrics seperated by space')
    arguments = parser.parse_args()

    nagiosResponse = NagiosResponse("All mandatory metrics are present!")

    try:
        tenants = requests.get('https://' + utils.MAIN_ADDRESS + utils.TENANT_API).json()
        #tenants = utils.removeNameFromJSON(tenants, utils.SUPERPOEM)

        for tenant in tenants:
            #print("Currently checking : " + tenant['name']) # HELP PRINT

            # Check mandatory metrics
            try:
                metrics = requests.get('https://' + tenant['domain_url'] + utils.METRICS_API).json()
                
                missing_metrics = arguments.manmetrics.copy()
                for metric in metrics:
                    if metric['name'] in arguments.manmetrics:
                        missing_metrics.remove(metric['name'])

                for metric in missing_metrics:
                    nagiosResponse.setCode(nagiosResponse.CRITICAL)
                    nagiosResponse.writeCriticalMessage('Customer: ' + tenant['name'] + ' - Metric %s is missing!' % metric)

            except requests.exceptions.RequestException as e:
                nagiosResponse.setCode(nagiosResponse.CRITICAL)
                nagiosResponse.writeCriticalMessage('Customer: ' + tenant['name'] + ' - cannot connect to %s: %s' % ('https://' + tenant['domain_url'] + utils.METRICS_API,
                                                            errmsg_from_excp(e)))
            except ValueError as e:
                nagiosResponse.setCode(nagiosResponse.CRITICAL)
                nagiosResponse.writeCriticalMessage('Customer: ' + tenant['name'] + ' - %s - %s' % (utils.METRICS_API, errmsg_from_excp(e)))


    except requests.exceptions.RequestException as e:
        nagiosResponse.setCode(nagiosResponse.CRITICAL)
        nagiosResponse.writeCriticalMessage('Critical - cannot connect to %s: %s' % ('https://' + utils.MAIN_ADDRESS + utils.TENANT_API,
                                                    errmsg_from_excp(e)))
    except ValueError as e:
        nagiosResponse.setCode(nagiosResponse.CRITICAL)
        nagiosResponse.writeCriticalMessage('Critical - %s - %s' % (utils.TENANT_API, errmsg_from_excp(e)))

    print(nagiosResponse.getMsg())
    raise SystemExit(nagiosResponse.getCode())

if __name__ == "__main__":
    main()