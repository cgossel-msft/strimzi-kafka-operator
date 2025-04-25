/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.model;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Microsoft private key and cert with full chain in PEM format.
 */
public class MicrosoftPemPrivateCert {
    private static final String INTERNAL_CERT_ENV = "MSFT_KAFKA_INTERNAL_CERT";
    private static final String PEM_PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_PRIVATE_KEY_END = "-----END PRIVATE KEY-----";
    private static final String PEM_CERT_END = "-----END CERTIFICATE-----";

    private final String key;
    private final byte[] keyBytes;
    private final String chain;
    private final byte[] chainBytes;
    private final X509Certificate chainCert;
    private final Set<byte[]> chainSet;
    private final Set<X509Certificate> chainCertSet;

    /**
     * Constructor
     * 
     * @param key   the key as PEM string
     * @param chain the public chain as a PEM string
     */
    public MicrosoftPemPrivateCert(String key, String chain) {
        this.key = key;
        this.chain = chain;
        this.keyBytes = this.key.getBytes(StandardCharsets.US_ASCII);
        this.chainBytes = this.chain.getBytes(StandardCharsets.US_ASCII);

        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            this.chainCert = (X509Certificate) certificateFactory
                    .generateCertificate(new ByteArrayInputStream(this.chainBytes));
        } catch (CertificateException e) {
            throw new RuntimeException("Bad/corrupt certificate found in data.");
        }

        this.chainSet = new HashSet<>();
        var partialCertSet = this.chain.split(PEM_CERT_END);
        for (String partialCert : partialCertSet) {
            if (partialCert != null && !partialCert.isBlank()) {
                this.chainSet.add((partialCert + PEM_CERT_END).getBytes(StandardCharsets.US_ASCII));
            }
        }

        this.chainCertSet = this.chainSet.stream().map(entry -> {
            try {
                return Ca.x509Certificate(entry);
            } catch (CertificateException e) {
                throw new RuntimeException("Bad/corrupt certificate.");
            }
        }).collect(Collectors.toSet());
    }

    /**
     * The private key
     * 
     * @return private key as PEM string.
     */
    public String key() {
        return this.key;
    }

    /**
     * The private key
     * 
     * @return the private key as PEM bytes
     */
    public byte[] keyAsBytes() {
        return this.keyBytes.clone();
    }

    /**
     * The private key.
     * 
     * @return private key stripped of PEM headers
     */
    public String strippedKey() {
        return this.key
                .replace(PEM_PRIVATE_KEY_BEGIN, "")
                .replaceAll(System.lineSeparator(), "")
                .replace(PEM_PRIVATE_KEY_END, "");
    }

    /**
     * The public cert chain
     * 
     * @return the public cert chain as a PEM string
     */
    public String chain() {
        return this.chain;
    }

    /**
     * The public cert chain
     * 
     * @return the public cert chain as PEM bytes
     */
    public byte[] chainAsBytes() {
        return this.chainBytes.clone();
    }

    /**
     * The public cert chain
     * 
     * @return the public cert chain as a single x509
     */
    public X509Certificate chainAsCert() {
        return this.chainCert;
    }

    /**
     * The public cert chain
     * 
     * @return the public cert chain split into a set of PEM byte arrays, one for
     *         each cert in the chain
     */
    public Set<byte[]> chainAsSet() {
        return new HashSet<>(this.chainSet);
    }

    /**
     * The public cert chain
     * 
     * @return the public cert chain split into a set of x509 certs
     */
    public Set<X509Certificate> chainAsCertSet() {
        return new HashSet<>(this.chainCertSet);
    }

    /**
     * Get the microsoft internal kafka private cert
     * 
     * @return the PEM key and chain for the microsoft internal kafka private cert
     */
    public static MicrosoftPemPrivateCert loadInternal() {
        try {
            String certPath = System.getenv(INTERNAL_CERT_ENV);
            String certString = Files.readString(Path.of(certPath));
            int privateStart = certString.indexOf(PEM_PRIVATE_KEY_BEGIN);
            int privateEnd = certString.indexOf(PEM_PRIVATE_KEY_END) + PEM_PRIVATE_KEY_END.length();
            String privateKeyString = certString.substring(privateStart, privateEnd);
            String certChainString = certString.substring(0, privateStart)
                    + certString.substring(privateEnd);
            return new MicrosoftPemPrivateCert(privateKeyString, certChainString);
        } catch (Throwable e) {
            throw new RuntimeException("Could not read microsoft internal cert", e);
        }
    }
}
