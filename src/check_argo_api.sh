#!/bin/bash

PROGNAME=`basename $0`
PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0.0"
NAGIOS_OK=0
NAGIOS_WARNING=1
NAGIOS_ERROR=2
NAGIOS_UNKNOWN=3

print_usage() {
  echo "Usage: $PROGNAME [-url API endpoint] [-auth_token ewrwerew2332] [-day days to check (ex. yesterday, 2 days ago) default yesterday] [-debug on or off (default off)]" 
}

print_help() {
	echo $PROGNAME $REVISION
	echo ""
	print_usage
	echo ""
	echo "This plugin checks ARGO api if has A/R results for the specified day"
	echo ""
	exit $NAGIOS_OK
}


if [ $# -eq 0 ]
  then
    echo "Problem: No arguments supplied"
    print_usage
    exit 2
fi

while test -n "$1"; do
    case "$1" in
        --help)
            print_help
            exit $NAGIOS_OK
            ;;
        -h)
            print_help
            exit $NAGIOS_OK
            ;;
        --version)
            echo $PROGNAME $REVISION
            exit $NAGIOS_OK
            ;;
        -V)
            echo $PROGNAME $REVISION
            exit $NAGIOS_OK
            ;;
        -url)
            CHECK_URL=$2
            shift
            ;;
        -auth_token)
            AUTH_TOKEN=$2
            shift
            ;;
        -day)
            CHECK_DAY=$2
            shift
            ;;
        -debug)
            DEBUG=$2
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            print_usage
            exit $NAGIOS_UNKNOWN
            ;;
    esac
    shift
done

if [ -z $CHECK_URL ] || [ -z $AUTH_TOKEN ];then
    echo "Problem: You must at least define the API URL and the auth token"
    print_usage
    exit $NAGIOS_ERROR
    
fi

if [ -z "$CHECK_DAY" ]
  then
    CHECK_DAY="yesterday"
fi

if [ -z "$DEBUG" ]
  then
    DEBUG="off"
fi

day_start=$(date --utc --date="$CHECK_DAY" +"%Y-%m-%dT00:00:00Z") 
day_end=$(date --utc --date="$CHECK_DAY" +"%Y-%m-%dT23:59:59Z") 
API_URL="$CHECK_URL?start_time=$day_start&end_time=$day_end&granularity=daily"

STRING="availability"
curlResult=`curl --connect-timeout 10 -s  -X GET -H "Accept:application/json" -H "Content-Type:application/json" -H "x-api-key: $AUTH_TOKEN" $API_URL`

if [ $DEBUG == "on"  ]
  then
   echo "API URL endpoint: $API_URL"
   echo "DAY To check: $CHECK_DAY"
   echo "Token provided: $AUTH_TOKEN"
   echo "Json answer: $curlResult"
fi

if [ $? != 0 ]
then
    echo "ERROR: Curl connection failure."
    exit $NAGIOS_ERROR
fi

if ( echo $curlResult | egrep -q "$STRING" )
then
    echo "OK"
    exit $NAGIOS_OK
else
    echo "ERROR: String \"$STRING\" not found."
    exit $NAGIOS_ERROR
fi

