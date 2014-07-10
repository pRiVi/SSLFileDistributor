#!/bin/sh
#
# mkca.sh -- make CA key/cert
#

# Key lenght in bits
KEYBITS=2048

# Validity period in days
DAYS=9200

# CRL distribution points separated with commas
# Example: CRLS=http://nodomain/crl.pem,ldap://nodomain
# Leave empty or comment out, if you don't need
#CRLS=http://nodomain/crl.pem

#######################################################

CONF=CA.cnf

# Get password
stty -echo
echo -n "Enter CA password !!! AT LEAST 4 CHARACTERS !!! : "; read PASS
echo
echo -n "Enter CA password !!! AT LEAST 4 CHARACTERS !!! (verify): "; read PASSV
echo
stty echo
if [ "$PASS" != "$PASSV" ]; then
	echo "Verify failure!"
	exit 1
fi

# Generate private key of KEYBITS bits
openssl genrsa -passout pass:$PASS -out private/ca.key -des3 $KEYBITS

# Generate certificate request and sign it
openssl req -new -sha256 -config $CONF -passin pass:$PASS -key private/ca.key \
	-out private/ca.csr
if [ "$CRLS" ]; then
	CRLS=`echo URI:$CRLS | sed 's/,/,URI:/g'`
	export CRL_DISTPOINTS=$CRLS
	openssl x509 -passin pass:$PASS -req -sha256 -days $DAYS -in private/ca.csr \
	-signkey private/ca.key -extfile $CONF -extensions x509v3_CA_CRL \
	-out ca.crt
else
	openssl x509 -passin pass:$PASS -req -sha256 -days $DAYS -in private/ca.csr \
	-signkey private/ca.key -extfile $CONF -extensions x509v3_CA \
	-out ca.crt
fi
chmod 600 private/*
