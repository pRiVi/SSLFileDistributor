#!/bin/sh
#
# sign.sh -- sign certificates
#

# Validity period in days
DAYS=750

 
######################################

if [ ! -f ca.crt ]; then
        echo "No CA certificate found, run mkca.sh first"
        exit 1
fi
CSR=$1
CONFIG=CA.cnf
if [ ! -f "$CSR" ]; then
	echo "CSR not found: $CSR"
	echo "Usage: sign.sh request [-ip|-dns|-email name]"; exit 1
fi
case $CSR in
        *.csr ) CERT="`echo $CSR | sed -e 's/\.csr/.crt/'`" ;;
        *) CERT="$CSR.crt" ;;
esac

if [ "$2" ]; then
	if [ ! "$3" ]; then
		echo "Missing subjectAltName extension parameter"
		echo "Usage: sign.sign request [-ip|-dns|-email name]"; exit 1
	fi
	case $2 in
		-ip)
			NAME=CERTIP
			PARAMETER=$3
			EXT=x509v3_IPAddr
			;;
		-dns)
			NAME=CERTNAME
			PARAMETER=$3
			EXT=x509v3_DNS
			;;
		-email)
			NAME=CERTEMAIL
			PARAMETER=$3
			EXT=x509v3_Email
			;;
		*)
			echo "Illegal subjectAltName extension $2"	
			echo "Usage: sign.sign request [-ip|-dns|-email name]"
			exit 1
			;;
	esac

fi
if [ "$2" ]; then
	eval export $NAME=$PARAMETER
	openssl ca -batch -passin pass:abcd -days $DAYS -config $CONFIG -extensions $EXT \
		-out $CERT -infiles $1
else
	openssl ca -passin pass:abcd -days $DAYS -config $CONFIG -out $CERT -infiles $1
fi
