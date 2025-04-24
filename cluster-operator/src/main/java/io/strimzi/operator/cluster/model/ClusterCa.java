/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.api.kafka.model.common.CertificateExpirationPolicy;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.certs.Subject;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.PasswordGenerator;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Represents the Cluster CA
 */
public class ClusterCa extends Ca {
    private static final CertAndKey EMPTY = new CertAndKey(new byte[0], new byte[0]);

    /**
     * Constructor
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param clusterName           Name of the Kafka cluster
     * @param caCertSecret          Name of the CA public key secret
     * @param caKeySecret           Name of the CA private key secret
     */
    public ClusterCa(Reconciliation reconciliation, CertManager certManager, PasswordGenerator passwordGenerator, String clusterName, Secret caCertSecret, Secret caKeySecret) {
        this(reconciliation, certManager, passwordGenerator, clusterName, caCertSecret, caKeySecret, CertificateAuthority.DEFAULT_CERTS_VALIDITY_DAYS, CertificateAuthority.DEFAULT_CERTS_RENEWAL_DAYS, true, null);
    }

    /**
     * Constructor
     *
     * @param reconciliation        Reconciliation marker
     * @param certManager           Certificate manager instance
     * @param passwordGenerator     Password generator instance
     * @param clusterName           Name of the Kafka cluster
     * @param clusterCaCert         Secret with the public key
     * @param clusterCaKey          Secret with the private key
     * @param validityDays          Validity days
     * @param renewalDays           Renewal days (how many days before expiration should the CA be renewed)
     * @param generateCa            Flag indicating if Strimzi CA should be generated or custom CA is used
     * @param policy                Renewal policy
     */
    public ClusterCa(Reconciliation reconciliation, CertManager certManager,
                     PasswordGenerator passwordGenerator,
                     String clusterName,
                     Secret clusterCaCert,
                     Secret clusterCaKey,
                     int validityDays,
                     int renewalDays,
                     boolean generateCa,
                     CertificateExpirationPolicy policy) {
        super(reconciliation, certManager, passwordGenerator,
                "cluster-ca",
                AbstractModel.clusterCaCertSecretName(clusterName),
                clusterCaCert,
                AbstractModel.clusterCaKeySecretName(clusterName),
                clusterCaKey, validityDays, renewalDays, generateCa, policy);
    }

    @Override
    public String toString() {
        return "cluster-ca";
    }

    @Override
    protected String caName() {
        return "Cluster CA";
    }

    /**
     * Prepares the Cruise Control certificate. It either reuses the existing certificate, renews it or generates new
     * certificate if needed.
     *
     * @param namespace                             Namespace of the Kafka cluster
     * @param clusterName                           Name of the Kafka cluster
     * @param existingSecret                        Existing Secret with the existing certificates (or null if it does not exist yet)
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating whether we can do maintenance tasks or not
     *
     * @return  Map with CertAndKey object containing the public and private key
     *
     * @throws IOException  IOException is thrown when it is raised while working with the certificates
     */
    protected Map<String, CertAndKey> generateCcCerts(
            String namespace,
            String clusterName,
            Secret existingSecret,
            boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        return generateCerts(Set.of(new NodeRef(CruiseControl.COMPONENT_TYPE, 0, null, false, false)));
    }

    /**
     * Prepares the ZooKeeper node certificates. It either reuses the existing certificates, renews them or generates new
     * certificates if needed.
     *
     * @param namespace                             Namespace of the Kafka cluster
     * @param clusterName                           Name of the Kafka cluster
     * @param existingSecret                        Existing Secret with the existing certificates (or null if it does not exist yet)
     * @param nodes                                 Nodes that are part of the ZooKeeper cluster
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating whether we can do maintenance tasks or not
     *
     * @return  Map with CertAndKey objects containing the public and private keys for the different nodes
     *
     * @throws IOException  IOException is thrown when it is raised while working with the certificates
     */
    protected Map<String, CertAndKey> generateZkCerts(
            String namespace,
            String clusterName,
            Secret existingSecret,
            Set<NodeRef> nodes,
            boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        return generateCerts(nodes);
    }


    /**
     * Prepares the Kafka broker certificates. It either reuses the existing certificates, renews them or generates new
     * certificates if needed.
     *
     * @param namespace                             Namespace of the Kafka cluster
     * @param clusterName                           Name of the Kafka cluster
     * @param existingSecret                        Existing Secret with the existing certificates (or null if it does not exist yet)
     * @param nodes                                 Nodes that are part of the Kafka cluster
     * @param externalBootstrapAddresses            List of external bootstrap addresses (used for certificate SANs)
     * @param externalAddresses                     Map with external listener addresses for the different nodes (used for certificate SANs)
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating whether we can do maintenance tasks or not
     *
     * @return  Map with CertAndKey objects containing the public and private keys for the different brokers
     *
     * @throws IOException  IOException is thrown when it is raised while working with the certificates
     */
    protected Map<String, CertAndKey> generateBrokerCerts(
            String namespace,
            String clusterName,
            Secret existingSecret,
            Set<NodeRef> nodes,
            Set<String> externalBootstrapAddresses,
            Map<Integer, Set<String>> externalAddresses,
            boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        return generateCerts(nodes);
    }

    @Override
    protected String caCertGenerationAnnotation() {
        return ANNO_STRIMZI_IO_CLUSTER_CA_CERT_GENERATION;
    }

    /**
     * Copy already existing certificates from provided Secret based on number of effective replicas
     * and maybe generate new ones for new replicas (i.e. scale-up).
     *
     * @param reconciliation                        Reconciliation marker
     * @param nodes                                 List of nodes for which the certificates should be generated
     * @param subjectFn                             Function to generate certificate subject for given node / pod
     * @param secret                                Secret with certificates
     * @param isMaintenanceTimeWindowsSatisfied     Flag indicating if we are inside a maintenance window or not
     *
     * @return  Returns map with node certificates which can be used to create or update the certificate secret
     *
     * @throws IOException  Throws IOException when working with files fails
     */
    /* test */ Map<String, CertAndKey> maybeCopyOrGenerateCerts(
        Reconciliation reconciliation,
        Set<NodeRef> nodes,
        Function<NodeRef, Subject> subjectFn,
        Secret secret,
        boolean isMaintenanceTimeWindowsSatisfied
    ) throws IOException {
        // Maps for storing the certificates => will be used in the new or updated secret. This map is filled in this method and returned at the end.
        Map<String, CertAndKey> certs = new HashMap<>();

        // Temp files used when we need to generate new certificates
        File brokerCsrFile = Files.createTempFile("tls", "broker-csr").toFile();
        File brokerKeyFile = Files.createTempFile("tls", "broker-key").toFile();
        File brokerCertFile = Files.createTempFile("tls", "broker-cert").toFile();
        File brokerKeyStoreFile = Files.createTempFile("tls", "broker-p12").toFile();

        for (NodeRef node : nodes)  {
            String podName = node.podName();
            Subject subject = subjectFn.apply(node);

            if (!this.certRenewed() // No CA renewal is happening
                    && secret != null && secret.getData() != null // Secret exists and has some data
                    && secretEntryExists(secret, podName, SecretEntry.CRT) // The secret has the public key for this pod
                    && secretEntryExists(secret, podName, SecretEntry.KEY) // The secret has the private key for this pod
                    && !hasCaCertGenerationChanged(secret) // The generation on the Secret is the same as the CA has
            )   {
                // A certificate for this node already exists, so we will try to reuse it
                LOGGER.debugCr(reconciliation, "Certificate for node {} already exists", node);

                CertAndKey certAndKey = asCertAndKey(secret.getData(), podName);

                List<String> reasons = new ArrayList<>(2);

                if (certSubjectChanged(certAndKey, subject, podName))   {
                    reasons.add("DNS names changed");
                }

                if (isExpiring(secret, podName + ".crt") && isMaintenanceTimeWindowsSatisfied)  {
                    reasons.add("certificate is expiring");
                }

                if (renewalType.equals(RenewalType.CREATE)) {
                    reasons.add("certificate added");
                }

                if (!reasons.isEmpty())  {
                    LOGGER.infoCr(reconciliation, "Certificate for pod {} need to be regenerated because: {}", podName, String.join(", ", reasons));

                    CertAndKey newCertAndKey = generateSignedCert(subject, brokerCsrFile, brokerKeyFile, brokerCertFile, brokerKeyStoreFile);
                    certs.put(podName, newCertAndKey);
                }   else {
                    certs.put(podName, certAndKey);
                }
            } else {
                // A certificate for this node does not exist or it the CA got renewed, so we will generate new certificate
                LOGGER.debugCr(reconciliation, "Generating new certificate for node {}", node);
                CertAndKey k = generateSignedCert(subject, brokerCsrFile, brokerKeyFile, brokerCertFile, brokerKeyStoreFile);
                certs.put(podName, k);
            }
        }

        // Delete the temp files used to generate new certificates
        delete(reconciliation, brokerCsrFile);
        delete(reconciliation, brokerKeyFile);
        delete(reconciliation, brokerCertFile);
        delete(reconciliation, brokerKeyStoreFile);

        return certs;
    }

    /**
     * Return given secret for pod as a CertAndKey object
     *
     * @param certificateData   The Map with the certificate data from the Kubernetes Secret(s)
     * @param podName           Name of the pod
     *
     * @return  CertAndKey instance
     */
    private static CertAndKey asCertAndKey(Map<String, String> certificateData, String podName) {
        String keyData = certificateData.get(SecretEntry.KEY.asKey(podName));
        if (keyData == null) {
            throw new RuntimeException("Certificate for node " + podName + " is missing the private key");
        }

        String certData = certificateData.get(SecretEntry.CRT.asKey(podName));
        if (certData == null) {
            throw new RuntimeException("Certificate for node " + podName + " is missing the public key");
        }

        return new CertAndKey(Util.decodeBytesFromBase64(keyData), Util.decodeBytesFromBase64(certData));
    }

    /**
     * Checks whether subject alternate names changed and certificate needs a renewal
     *
     * @param certAndKey        Current certificate
     * @param desiredSubject    Desired subject alternate names
     * @param podName           Name of the pod to which this certificate belongs (used for log messages)
     *
     * @return  True if the subjects are different, false otherwise
     */
    /* test */ boolean certSubjectChanged(CertAndKey certAndKey, Subject desiredSubject, String podName)    {
        Collection<String> desiredAltNames = desiredSubject.subjectAltNames().values();
        Collection<String> currentAltNames = getSubjectAltNames(certAndKey.cert());

        if (currentAltNames != null && desiredAltNames.containsAll(currentAltNames) && currentAltNames.containsAll(desiredAltNames))   {
            LOGGER.traceCr(reconciliation, "Alternate subjects match. No need to refresh cert for pod {}.", podName);
            return false;
        } else {
            LOGGER.infoCr(reconciliation, "Alternate subjects for pod {} differ", podName);
            LOGGER.infoCr(reconciliation, "Current alternate subjects: {}", currentAltNames);
            LOGGER.infoCr(reconciliation, "Desired alternate subjects: {}", desiredAltNames);
            return true;
        }
    }

    /**
     * Extracts the alternate subject names out of existing certificate
     *
     * @param certificate   Existing X509 certificate as a byte array
     *
     * @return  List of certificate Subject Alternate Names
     */
    private List<String> getSubjectAltNames(byte[] certificate) {
        List<String> subjectAltNames = null;

        try {
            X509Certificate cert = x509Certificate(certificate);
            Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
            subjectAltNames = altNames.stream()
                    .filter(name -> name.get(1) instanceof String)
                    .map(item -> (String) item.get(1))
                    .collect(Collectors.toList());
        } catch (CertificateException | RuntimeException e) {
            // TODO: We should mock the certificates properly so that this doesn't fail in tests (not now => long term :-o)
            LOGGER.debugCr(reconciliation, "Failed to parse existing certificate", e);
        }

        return subjectAltNames;
    }


    private static Map<String, CertAndKey> generateCerts(Set<NodeRef> nodes) {
        var certs = new HashMap<String, CertAndKey>(nodes.size());
        for (var node : nodes) {
            certs.put(node.podName(), EMPTY);
        }

        return certs;
    }

    /**
     * Remove old certificates that are stored in the CA Secret matching the "ca-YYYY-MM-DDTHH-MM-SSZ.crt" naming pattern.
     * NOTE: mostly used when a CA certificate is renewed by replacing the key
     */
    public void maybeDeleteOldCerts() {
    }
}