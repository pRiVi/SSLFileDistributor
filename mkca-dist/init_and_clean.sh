#!/bin/bash
rm -R newcerts/* -R reqs/* vpnclients/* private/* index.txt.old index.txt.attr.old serial.old ca.crl ca.crt
echo 00 >serial
> index.txt

