#!/bin/sh
echo ""
echo "====================== Cryptographic Keys Generator ======================"
echo "                        # By Círculo de Crédito #"
echo ""

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Starting generation of cryptographic keys ..."
echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Setting and exporting shell variables ..."

export KEYS_DIRECTORY="Circulo_Credito_Keys-$(date +'%Y%m%dT%H%M%S')"
export PRIVATE_KEY_FILE=private_key.pem
export CERTIFICATE_FILE=public_certificate.pem
export CERTIFICATE_SUBJECT=/C=MX/ST=MX/L=MX/O=CDC/CN=CDC
export PKCS12_FILE=keystore.p12
export ALIAS=cdc

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Shell variables were set and exported successfully!"

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Creating keys directory: '$KEYS_DIRECTORY/'"

mkdir ./$KEYS_DIRECTORY

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Generating Private Key with EllipticCurve-384 ..."

# Generate private key
openssl ecparam -name secp384r1 -genkey -out ./$KEYS_DIRECTORY/$PRIVATE_KEY_FILE

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Private Key './$KEYS_DIRECTORY/$PRIVATE_KEY_FILE' generated successfully!"

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Generating Public Certificate from Private Key ..."

# Generate public certifiate from private key
openssl req -new -x509 -days 365 -key ./$KEYS_DIRECTORY/$PRIVATE_KEY_FILE -out ./$KEYS_DIRECTORY/$CERTIFICATE_FILE -subj $CERTIFICATE_SUBJECT

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Public Certificate './$KEYS_DIRECTORY/$CERTIFICATE_FILE' generated successfully!"

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Generating Keystore PKCS12 ..."

# Generate PKCS12 file from certificate and private key
openssl pkcs12 -export -out ./$KEYS_DIRECTORY/$PKCS12_FILE -inkey ./$KEYS_DIRECTORY/$PRIVATE_KEY_FILE -in ./$KEYS_DIRECTORY/$CERTIFICATE_FILE

echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Keystore PKCS12 './$KEYS_DIRECTORY/$PKCS12_FILE' generated successfully!"
echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO ] Cryptographic keys generation finished!"
echo ""
