/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.auth;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.Util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Represents the identity used during TLS client authentication.
 * This consists of an X509 end-entity certificate, corresponding private key,
 * and a (possibly empty) chain of X509 intermediate CA certificates, all in PEM
 * format.
 */
public class PemAuthIdentity {
    /**
     * Filename suffix for certificate chain as PEM
     */
    public static final String PEM_SUFFIX = "pem";
    private static final String COSMIC_CERT_ENV = "COSMIC_KAFKA_INTERNAL_CERT";
    private static final String PEM_PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_PRIVATE_KEY_END = "-----END PRIVATE KEY-----";
    private final byte[] privateKeyAsPemBytes;
    private final byte[] certificateChainAsPemBytes;
    private final String secretCertName;
    private final String secretName;

    /**
     * Constructs the PemAuthIdentity.
     * 
     * @param secret         Kubernetes Secret containing the Cluster Operator
     *                       public and private key
     * @param secretCertName Key in the Kubernetes Secret that is associated with
     *                       the requested identity
     */
    private PemAuthIdentity(Secret secret, String secretCertName) {
        Objects.requireNonNull(secret, "Cannot extract auth identity from null secret.");
        this.secretCertName = secretCertName;
        this.secretName = secret.getMetadata().getName();
        var privateCert = getCosmicKafkaCert();
        this.privateKeyAsPemBytes = privateCert.key.getBytes(StandardCharsets.US_ASCII);
        this.certificateChainAsPemBytes = privateCert.chain.getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Returns the instance of PemAuthIdentity that represents the identity of the
     * cluster operator during TLS client authentication.
     *
     * @param secret Kubernetes Secret containing the client authentication identity
     *
     * @return PemAuthIdentity to use as the client authentication identity during
     *         TLS authentication
     */
    public static PemAuthIdentity clusterOperator(Secret secret) {
        return new PemAuthIdentity(secret, "cluster-operator");
    }

    /**
     * Returns the instance of PemAuthIdentity that represents the identity of the
     * entity (i.e. user or topic) operator during TLS client authentication.
     *
     * @param secret Kubernetes Secret containing the client authentication identity
     *
     * @return PemAuthIdentity to use as the client authentication identity during
     *         TLS authentication
     */
    public static PemAuthIdentity entityOperator(Secret secret) {
        return new PemAuthIdentity(secret, "entity-operator");
    }

    /**
     * End-entity certificate and (possibly empty) chain of intermediate CA
     * certificates for this authentication identity.
     *
     * @return The certificate chain for this authentication identity as a byte
     *         array
     */
    public byte[] certificateChainAsPemBytes() {
        return certificateChainAsPemBytes;
    }

    /**
     * End-entity certificate and (possibly empty) chain of intermediate CA
     * certificates for this authentication identity.
     *
     * @return The certificate chain for this authentication identity as a String
     */
    public String certificateChainAsPem() {
        return Util.fromAsciiBytes(certificateChainAsPemBytes);
    }

    /**
     * Private key corresponding to the end-entity certificate for this
     * authentication identity.
     *
     * @return The private key for this authentication identity as a byte array
     */
    public byte[] privateKeyAsPemBytes() {
        return privateKeyAsPemBytes;
    }

    /**
     * Private key corresponding to the end-entity certificate for this
     * authentication identity.
     *
     * @return The private key for this authentication identity as a String
     */
    public String privateKeyAsPem() {
        return Util.fromAsciiBytes(privateKeyAsPemBytes);
    }

    /**
     * KeyStore to use for TLS connections.
     * 
     * @return KeyStore file in PEM format
     */
    public byte[] pemKeyStore() {
        return (privateKeyAsPem() + certificateChainAsPem()).getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * KeyStore to use for TLS connections.
     *
     * @param password to use to secure the KeyStore
     *
     * @return KeyStore file in JKS format
     * @throws GeneralSecurityException if something goes wrong when creating the
     *                                  truststore
     * @throws IOException              if there is an I/O or format problem with
     *                                  the data used to load the truststore.
     */
    public KeyStore jksKeyStore(char[] password) throws GeneralSecurityException, IOException {
        String strippedPrivateKey = privateKeyAsPem()
                .replace(PEM_PRIVATE_KEY_BEGIN, "")
                .replaceAll(System.lineSeparator(), "")
                .replace(PEM_PRIVATE_KEY_END, "");
        byte[] decodedKey = Base64.getDecoder().decode(strippedPrivateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        final PrivateKey key = keyFactory.generatePrivate(keySpec);

        KeyStore coKeyStore = KeyStore.getInstance("JKS");
        coKeyStore.load(null);
        coKeyStore.setKeyEntry("cluster-operator", key, password, new Certificate[]{certificateChain()});
        return coKeyStore;
    }

    /**
     * End-entity certificate and (possibly empty) chain of intermediate CA
     * certificates for this authentication identity.
     * This also validates that the certificate chain is a valid X509 certificate.
     *
     * @return The certificate chain for this authentication identity as a
     *         X509Certificate
     */
    public X509Certificate certificateChain() {
        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(certificateChainAsPemBytes));
        } catch (CertificateException e) {
            throw new RuntimeException(
                    "Bad/corrupt certificate found in data." + secretCertName + ".crt of Secret "
                            + secretName);
        }
    }

    protected static PemPrivateCert getCosmicKafkaCert() {
        try {
            String certPath = System.getenv(COSMIC_CERT_ENV);
            String certString = Files.readString(Path.of(certPath));
            int privateStart = certString.indexOf(PEM_PRIVATE_KEY_BEGIN);
            int privateEnd = certString.indexOf(PEM_PRIVATE_KEY_END) + PEM_PRIVATE_KEY_END.length();
            String privateKeyString = certString.substring(privateStart, privateEnd);
            String certChainString = certString.substring(0, privateStart)
                    + certString.substring(privateEnd);
            return new PemPrivateCert(privateKeyString, certChainString);
        } catch (Throwable e) {
            throw new RuntimeException("Could not read cosmic internal cert", e);
        }
    }

    protected static record PemPrivateCert(String key, String chain) {
    };
}