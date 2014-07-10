#!/bin/sh
#
# mkcert.sh -- make client certificate PKCS#12 bundle
#

# countryName
COUNTRY="DE"

# stateOrProvinceName
STATE=Bavaria

# localityName
LOCALITY=DE

# organizationName
ORGANIZATION="sayTEC GmbH"

# organizationalUnitName
ORGANIZATIONAL_UNIT="sayTRUST"


#####################################


if [ ! -f ca.crt ]; then
	echo "No CA certificate found, run mkca.sh first"
	exit 1
fi
if [ ! "$2" ]; then
	echo "Usage: $0 -ip|-dns|-email name [keybits]"
	exit 1
fi
case $1 in
	-ip|-dns|-email)
		;;
	*)
		echo "Illegal subjectAltName extension $1"
		echo "Usage: $0 -ip|-dns|-email name [keybits]"
		exit 1
		;;
esac
EXT=$1
NAME=$2
KEYBITS=2048
SERIAL=`cat serial`

if [ "$3" ]; then
	KEYBITS=$3
fi

# Generate key and request
mkdir vpnclients/$NAME
openssl genrsa -passout pass:abcd -out vpnclients/$NAME/$NAME.key $KEYBITS >/dev/null 2>&1

CONFIG=.$$client.cnf
cat << _EOF_ > $CONFIG
[ req ]
prompt = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
_EOF_
if [ "$COUNTRY" ]; then
	echo "C=$COUNTRY" >> $CONFIG
fi
if [ "$STATE" ]; then
	echo "ST=$STATE" >> $CONFIG
fi
if [ "$LOCALITY" ]; then
	echo "L=$LOCALITY" >> $CONFIG
fi
if [ "$ORGANIZATION" ]; then
	echo "O=$ORGANIZATION" >> $CONFIG
fi
if [ "$OUNIT" ]; then
	echo "OU=$OUNIT" >> $CONFIG
fi
echo "CN=$NAME" >> $CONFIG

openssl req -passin pass:abcd -new -sha256 -key vpnclients/$NAME/$NAME.key \
	-out vpnclients/$NAME/$NAME.csr -config $CONFIG >/dev/null 2>&1
rm -rf $CONFIG

# Sign the request
echo
echo "Signing certificate, enter the CA password $NAME $EXT"
./sign.shell.sh vpnclients/$NAME/$NAME.csr $EXT $NAME


# Generate pkcs12
echo
echo "Generating PKCS#12"
openssl pkcs12 -passout pass: -passin pass:abcd -export -certfile ca.crt \
	-inkey vpnclients/$NAME/$NAME.key \
	-in vpnclients/$NAME/$NAME.crt \
	-out vpnclients/$NAME/$NAME.p12

echo
echo "PKCS#12 file written in vpnclients/$NAME/$NAME.p12"
echo
