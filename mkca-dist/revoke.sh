#!/bin/sh
#
# revoke.sh -- revoke certificates
#

# Revocation list name
CRL_NAME=ca.crl

# Time before next CRL is due
# select CRL_DAYS or CRL_HOURS - not both
#CRL_DAYS=1
#CRL_HOURS=24


############################################

CONFIG=CA.cnf
if [ ! "$1" ]; then
	echo "Usage: $0 certificates"
	exit 1
fi

if [ "$CRL_DAYS" ]; then
	DUE=$(($CRL_DAYS*24))
elif [ "$CRL_HOURS" ]; then
	DUE=$CRL_HOURS
else
	DUE=999999
fi

if [ ! -f ca.crt ]; then
        echo "No CA certificate found, run mkca.sh first"
        exit 1
fi

stty -echo
echo -n "Enter PEM pass phrase: "; read PASS
stty echo
echo
for CERT in $@; do
	openssl ca -crlhours $DUE -config $CONFIG -passin pass:$PASS -revoke $CERT 
done
openssl ca -config $CONFIG -passin pass:$PASS -gencrl -out $CRL_NAME

