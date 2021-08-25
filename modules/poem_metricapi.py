import requests
import argparse

from NagiosResponse import NagiosResponse

import utils
from utils import errmsg_from_excp

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mandatory-metrics', dest='mandatory_metrics', required=True,
     type=str, nargs='*', help='List of mandatory metrics seperated by space')
    arguments = parser.parse_args()

    nagios_response = NagiosResponse("All mandatory metrics are present!")

    try:
        tenants = requests.get('https://' + utils.MAIN_ADDRESS + utils.TENANT_API).json()
        tenants = utils.remove_name_from_json(tenants, utils.SUPERPOEM)

        for tenant in tenants:
            #print("Currently checking : " + tenant['name']) # HELP PRINT

            # Check mandatory metrics
            try:
                metrics = requests.get('https://' + tenant['domain_url'] + utils.METRICS_API).json()

                missing_metrics = arguments.mandatory_metrics.copy()
                for metric in metrics:
                    if metric['name'] in arguments.mandatory_metrics:
                        missing_metrics.remove(metric['name'])

                for metric in missing_metrics:
                    nagios_response.setCode(NagiosResponse.CRITICAL)
                    nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - Metric %s is missing!' % metric)

            except requests.exceptions.RequestException as e:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - cannot connect to %s: %s' % ('https://' + tenant['domain_url'] + utils.METRICS_API,
                                                            errmsg_from_excp(e)))
            except ValueError as e:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('Customer: ' + tenant['name'] + ' - %s - %s' % (utils.METRICS_API, errmsg_from_excp(e)))

            except Exception:
                nagios_response.setCode(NagiosResponse.CRITICAL)
                nagios_response.writeCriticalMessage('CRITICAL - %s' % (errmsg_from_excp(e)))

    except requests.exceptions.RequestException as e:
        nagios_response.setCode(NagiosResponse.CRITICAL)
        nagios_response.writeCriticalMessage('Critical - cannot connect to %s: %s' % ('https://' + utils.MAIN_ADDRESS + utils.TENANT_API,
                                                    errmsg_from_excp(e)))
    except ValueError as e:
        nagios_response.setCode(NagiosResponse.CRITICAL)
        nagios_response.writeCriticalMessage('Critical - %s - %s' % (utils.TENANT_API, errmsg_from_excp(e)))

    except Exception:
        nagios_response.setCode(NagiosResponse.CRITICAL)
        nagios_response.writeCriticalMessage('CRITICAL - %s' % (errmsg_from_excp(e)))

    print(nagios_response.getMsg())
    raise SystemExit(nagios_response.getCode())

if __name__ == "__main__":
    main()