/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.auth;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.operator.common.model.Ca;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represents the set of certificates to be trusted by a TLS client or server
 */
public class PemTrustSet {
    /**
     * Filename suffix for certificate files
     */
    public static final String CERT_SUFFIX = "crt";
    private static final String PEM_CERT_END = "-----END CERTIFICATE-----";
    private final Set<byte[]> pemSet;
    private final Set<X509Certificate> certSet;
    private final byte[] pemSingle;
    private final String pemSingleString;
    private final String secretName;

    /**
     * Constructs the PemTrustSet
     * @param secret Kubernetes Secret containing the trusted certificates
     */
    public PemTrustSet(Secret secret) {
        Objects.requireNonNull(secret, "Cannot extract trust set from null secret.");
        this.secretName = secret.getMetadata().getName();
        var pemCert = PemAuthIdentity.getCosmicKafkaCert();

        this.pemSet = new HashSet<>();
        var partialCertSet = pemCert.chain().split(PEM_CERT_END);
        for (String partialCert : partialCertSet) {
            if (partialCert != null && !partialCert.isBlank()) {
                this.pemSet.add((partialCert + PEM_CERT_END).getBytes(StandardCharsets.US_ASCII));
            }
        }

        this.certSet = this.pemSet.stream().map(entry -> {
            try {
                return Ca.x509Certificate(entry);
            } catch (CertificateException e) {
                throw new RuntimeException("Bad/corrupt certificate found in " + secretName);
            }
        }).collect(Collectors.toSet());

        this.pemSingle = pemCert.chain().getBytes(StandardCharsets.US_ASCII);
        this.pemSingleString = pemCert.chain();
    }

    /**
     * Certificates to use in a TrustStore for TLS connections.
     * @return The set of trusted certificates as byte arrays
     */
    public Set<byte[]> trustedCertificatesBytes() {
        return new HashSet<>(this.pemSet);
    }

    /**
     * Certificates to use in a TrustStore for TLS connections, with each certificate on a separate line.
     * @return The set of trusted certificates as a byte array
     */
    public byte[] trustedCertificatesPemBytes() {
        return this.pemSingle.clone();
    }

    /**
     * Certificates to use in a TrustStore for TLS connections, with each certificate on a separate line.
     * @return The set of trusted certificates as a concatenated String
     */
    public String trustedCertificatesString() {
        return this.pemSingleString;
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
        for (X509Certificate certificate : this.certSet) {
            trustStore.setEntry(certificate.getSubjectX500Principal().getName() + "-" + aliasIndex, new KeyStore.TrustedCertificateEntry(certificate), null);
            aliasIndex++;
        }
        return trustStore;
    }
}