# argo-probes

This package includes probes for ARGO internal services. 

Currently, there are probes for:

- ARGO EGI Connectors
- ARGO Messaging service
- ARGO Messaging Nagios publisher
- ARGO Web API
- POEM service
- Compute Engine dataflow
- Argo authentication service

## ARGO Messaging service

Probe is inspecting AMS service by trying to publish and consume randomly
generated messages. Probe creates a topic and subscription, generates random
100 messages with payload about 500 bytes that tries to publish to service
following immediate try of consuming them. If the integrity of messages is
preserved on publishing and consuming side, service is working fine and probe
will return successfull status.

The usage is:

```sh
$ usage: ams-probe [-h] [--host HOST] --token TOKEN --project PROJECT
                   [--topic TOPIC] [--subscription SUBSCRIPTION]
                   [--timeout TIMEOUT]

```

where:
- (--host): the FQDN of the AMS service. Default: messaging-devel.argo.grnet.gr
- (--token): secret used to authenticate to AMS service
- (--project): project created on AMS service
- (--topic): topic that will be created in project and that will hold published
             messages. Default: nagios_sensor_topic.
- (--subscription): subscription created for topic from which messages will be
                    pulled. Default: nagios_sensor_sub
- (--timeout): Timeout after connection is considered dead. Default: 180 

### Usage example

```sh
$ ./ams-probe --token T0K3N --host messaging-devel.argo.grnet.gr --project EGI --topic probetest --subscription probetestsub --timeout 30
```

## ARGO Messaging Nagios publisher

Probe is inspecting AMS publisher running on Nagios monitoring instances. It's
inspecting trends of published results for each spawned worker and raises
critical if number of published results of any worker is below expected
threshold. Additionally, it will raise warning if numbers are not yet available
i.e. ams-publisher has just started and has not yet published expected number
of results. It queries local inspection socket that publisher exposes and
reports back status with the help of NRPE Nagios system.

The usage is:

```sh
usage: amspub_check.py [-h] -s SOCKET -q QUERY -c THRESHOLD [-t TIMEOUT]
```

where:
- (-s): local path of publisher inspection socket
- (-q): simple query that can be specified multiple times consisted of worker name and identifier of published or consumed
    messages in specified minute interval, e.g. `w:metrics+g:published15`
    - `metrics` is name of worker that will be inspected
    - `published15` is identifier designating that caller is interested in number of
        published messages in last 15 minutes
- (-c): threshold corresponding to each query 
- (-t): optional timeout after which probe will no longer wait for answer from socket

### Usage example

```sh
./ams-publisher-probe -s /var/run/argo-nagios-ams-publisher/sock -q 'w:metrics+g:published180' -c 50000 -q 'w:alarms+g:published180' -c 1
```

## ARGO Web API 

This is a probe for checking AR and status reports are properly working. 
It checks if there are available AR and status data for a selected day. 

The usage of the script is:
```sh
$ usage: web-api [-h] [-H HOSTNAME] [--tenant TENANT] [--rtype RTYPE] [--token TOKEN]
              [--day DAY] [--unused-reports Report1 Report2] [-t TIMEOUT] [-v DEBUG]
```

where:

 - (-H): the hostname of the web api 
 - (--tenant): the tenant name (ex. EGI)
 - (--rtype): the report type (ar or status)
 - (--token): the authorization token
 - (--unused-reports): Report names that are not used anymore. 
 - (--day): the day to check (1,2 ..3 means 1 or 2 or 3 days back)
 - (-t): the timeout
 - (-v): prints some debug data when is set to on  (by default off)
 
### Usage example

```sh
$ ./web-api -H web-api.test.com --tenant tenantname --rtype ar --token 12321312313123 --unused-reports  Report1 Report2  --day 1 -t 180 -v
```

## POEM Service
This is a probe for checking if tenant certificates are valid, and if tenants contain mandatory metrics. The probe acutally consists of two probes, probe_cert which checks if the certificates are valid, and probe_metricapi which checks if tenants contain the mandatory metrics.

The usage of the script for poem_cert is:
```sh
$ usage: poem_cert.py [-h] [--cert CERT] [--key KEY] [--capath CAPATH]
                    [-t TIMEOUT]
```
where:

 - (--cert): Path to host certificate
 - (--key): Path to host key
 - (--capath): CAPATH
 - (-t): the timeout

The usage of the script for poem_metricapi is:
```sh
$ usage: poem_metricapi.py [-h]
                         [--mandatory-metrics [MANMETRICS [MANMETRICS ...]]]
```
where:

 - (--mandatory-metrics): List of mandatory metrics seperated by space
### Usage examples
```sh
$ ./poem_cert --cert /security/certificate.pem --key security/key.pem --capath security/certificates -t 180

$ ./poem_metricapi --mandatory-metrics metric1 metric2 metricN
```
## Compute Engine dataflow

This is a probe for checking the compute engine's dataflow, making sure that all components work as intented.
The checking involves the probe publishing a message to AMS, and expecting after some time, to find the same message produced by the system.If the message is identical, and has been delivered in reasonable time, then everything is ok, otherwise, we examine the result, to figure out, what went wrong with the system.

Usage of the script:
```sh
$ ce_check.py [-h] [-H HOSTNAME] [--project Project]  [--token TOKEN]
              [--push_topic Push Topic] [--pull_subscription Pull Subscription] [-t TIMEOUT]
			  
```
 - (-H): the hostname of the AMS endpoint.
 - (--project): the project that holds the topics and subscriptions.
 - (--token): the authorization token.
 - (--push_topic): the name of the topic, where the probe should publish its data.
 - (--pull_subscription): the name of the subscription, where the probe will check for system's response.
 - (--push_subscription): the name of the subscription, where the System will read from.
 - (-t): A timeout option(seconds) for AMS library requests.
 - (-i): a timewindow(seconds) between publishing and retrieving the message that is expected and considered 'healthy' for the system.
 
### Usage example
 
 ```sh
 $ ce_check -H ams-endpoint.gr --project TEST_PR --token test_token --push_topic test_topic --pull_subscription test_sub --push_subscription test_sub_2 -t 180 -i 500
 
 ```
 
 ## Argo Authentication Service

This is a probe for checking that the authentication service is able to perform mappings 
for both the Argo messaging service and the Argo web api.

Usage of the script:
```sh
$ authn_check.py [-h] --authn-host AUTHN_HOST --authn-port AUTHN_PORT
                      --cert CERT --key KEY --ams-token AMS_TOKEN
                      [--ams-service AMS_SERVICE] --ams-host AMS_HOST
                      --webapi-token WEB_API_TOKEN
                      [--webapi-service WEB_API_SERVICE] --webapi-host
                      WEB_API_HOST [--verify]
			  
```
 - (--authn-host): Authn host.
 - (--authn-port): Authn port.
 - (--cert): Path to the certificate file.
 - (--key): Path to the certificate's key.
 - (--ams-token): Expected ams token.
 - (--ams-service): The name of the service in authn(default is ams).
 - (--ams-host): The AMS host that authn should target.
 - (--webapi-token): Expected webapi token.
 - (--webapi-service): The name of the service in authn(default is web-api).
 - (--webapi-host): The WEB API host that authn should target.
 - (--verify): SSL verification(default is false).

### Usage example
 
 ```sh
 $ ./authn_check.py --authn-host 127.0.0.1 --authn-port 8081 
 -cert /path/to/hostcert.pem -key /path/to//hostkey.pem 
 --webapi-token tOk3n --webapi-host 127.0.0.1 --ams-token tOk3n
 --ams-host 127.0.0.1 --verify
 
 ```
