#!/usr/bin/env bash
set -e
set +x

# Parameters:
# $1: Path to the internal cert with private key
# $2: Path to the new keystore
# $3: Keystore password
function create_keystore()
{
    echo "Creating Cosmic keystore $2 from $1"
    rm -f "$2"
    ALIAS=$(basename "$1" .pem)
    RANDFILE=/tmp/.rnd openssl pkcs12 -export -in "$1" -out "$2" -name "$ALIAS" -password pass:"$3" -certpbe aes-128-cbc -keypbe aes-128-cbc -macalg sha256
}

# Parameters:
# $1: Path to the internal cert with private key
# $2: Path to the new truststore
# $3: Truststore password
function create_truststore()
{
    echo "Creating Cosmic truststore $2 from $1"

    # Disable FIPS if needed
    if [ "$FIPS_MODE" = "disabled" ]; then
        KEYTOOL_OPTS="${KEYTOOL_OPTS} -J-Dcom.redhat.fips=false"
    else
        KEYTOOL_OPTS=""
    fi

    SCRATCH="/tmp/cosmic-scratch"
    mkdir -p $SCRATCH
    BASE=$(basename "$1" .pem)
    i=1
    ALIAS="$BASE-$i"
    TEMP="$SCRATCH/$ALIAS.pem"

    # openssl x509 imports first public cert from stdin without closing or discarding
    # the rest of the input, so we can feed the cert bundle into a loop
    # via stdin and extract each public cert into its own TEMP file for processing
    while openssl x509 -out $TEMP 2> /dev/null; do
        keytool ${KEYTOOL_OPTS} -keystore "$2" -storepass "$3" -noprompt -import -file "$TEMP" -alias "$ALIAS" -storetype PKCS12
        rm -f "$TEMP"
        i=$((i+1))
        ALIAS="$BASE-$i"
        TEMP="$SCRATCH/$ALIAS.pem"
    done < $1
}

echo "Cosmic Kafka Cert Preparation"

KEYSTORE=/tmp/topic-operator/replication.keystore.p12
TRUSTSTORE=/tmp/topic-operator/replication.truststore.p12

create_keystore "$COSMIC_KAFKA_INTERNAL_CERT" "$KEYSTORE" "$CERTS_STORE_PASSWORD"

rm -f "$TRUSTSTORE"
create_truststore "$COSMIC_KAFKA_INTERNAL_CERT" "$TRUSTSTORE" "$CERTS_STORE_PASSWORD"