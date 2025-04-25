/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.auth;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.model.MicrosoftPemPrivateCert;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the set of certificates to be trusted by a TLS client or server
 */
public class PemTrustSet {
    /**
     * Filename suffix for certificate files
     */
    public static final String CERT_SUFFIX = "crt";
    private final MicrosoftPemPrivateCert cert;

    /**
     * Constructs the PemTrustSet
     * @param secret Kubernetes Secret containing the trusted certificates
     */
    public PemTrustSet(Secret secret) {
        Objects.requireNonNull(secret, "Cannot extract trust set from null secret.");
        this.cert = MicrosoftPemPrivateCert.loadInternal();
    }

    /**
     * Certificates to use in a TrustStore for TLS connections.
     * 
     * @return The set of trusted certificates as byte arrays
     */
    public Set<byte[]> trustedCertificatesBytes() {
        return this.cert.chainAsSet();
    }

    /**
     * Certificates to use in a TrustStore for TLS connections, with each certificate on a separate line.
     * @return The set of trusted certificates as a byte array
     */
    public byte[] trustedCertificatesPemBytes() {
        return this.cert.chainAsBytes();
    }

    /**
     * Certificates to use in a TrustStore for TLS connections, with each certificate on a separate line.
     * @return The set of trusted certificates as a concatenated String
     */
    public String trustedCertificatesString() {
        return this.cert.chain();
    }

    /**
     * TrustStore to use for TLS connections. This also validates each one is a valid certificate and
     * throws an exception if it is not.
     * @return TrustStore file in JKS format
     * @throws GeneralSecurityException if something goes wrong when creating the truststore
     * @throws IOException if there is an I/O or format problem with the data used to load the truststore.
     * This is not expected as the truststore is loaded with null parameter.
     */
    public KeyStore jksTrustStore() throws GeneralSecurityException, IOException {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null);
        int aliasIndex = 0;
        for (X509Certificate certificate : this.cert.chainAsCertSet()) {
            trustStore.setEntry(certificate.getSubjectX500Principal().getName() + "-" + aliasIndex,
                    new KeyStore.TrustedCertificateEntry(certificate), null);
            aliasIndex++;
        }
        return trustStore;
    }
}