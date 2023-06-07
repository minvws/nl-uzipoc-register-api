#!/bin/bash

set -e

SECRETS_DIR=secrets
SAML_DIR=saml

create_key_pair () {
  echo "generating keypair and certificate $1/$2 with CN:$3"
  openssl genrsa -out $1/$2.key 2048
  openssl rsa -in $1/$2.key -pubout > $1/$2.pub
  openssl req -new -sha256 \
    -key $1/$2.key \
    -subj "/C=US/CN=$3" \
    -out $1/$2.csr
  openssl x509 -req -days 500 -sha256 \
    -in $1/$2.csr \
    -CA $SECRETS_DIR/cacert.crt \
    -CAkey $SECRETS_DIR/cacert.key \
    -CAcreateserial \
    -out $1/$2.crt
  rm $1/$2.csr
}


###
 # Create ca for local selfsigned certificates
###
if [[ ! -f $SECRETS_DIR/cacert.crt ]]; then
  openssl genrsa -out $SECRETS_DIR/cacert.key 4096
	openssl req -x509 -new -nodes -sha256 -days 1024 \
	  -key $SECRETS_DIR/cacert.key \
	  -out $SECRETS_DIR/cacert.crt \
	  -subj "/CN=US/CN=uzipoc-register-ca"
fi

###
# saml idp
###
if [[ ! -f $SAML_DIR/idp/certs/sp.crt ]]; then
  mkdir -p $SAML_DIR/idp/certs
  create_key_pair $SAML_DIR/idp/certs "sp" "idp-sp"
fi

###
# saml idp tls
###
if [[ ! -f $SAML_DIR/idp/certs/tls.crt ]]; then
  mkdir -p $SAML_DIR/idp/certs
  create_key_pair $SAML_DIR/idp/certs "tls" "ipd-tls"
fi

###
# saml idp dv-cluster-cert
###
if [[ ! -f $SAML_DIR/idp/certs/dv.crt ]]; then
  mkdir -p $SAML_DIR/idp/certs
  create_key_pair $SAML_DIR/idp/certs "dv" "dv"
fi
