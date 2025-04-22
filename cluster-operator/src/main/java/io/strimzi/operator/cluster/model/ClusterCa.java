/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
// CHECKSTYLE_OFF: ParameterNumberCheck
package io.strimzi.operator.cluster.model;

import io.fabric8.kubernetes.api.model.Secret;
import io.strimzi.api.kafka.model.common.CertificateAuthority;
import io.strimzi.api.kafka.model.common.CertificateExpirationPolicy;
import io.strimzi.certs.CertAndKey;
import io.strimzi.certs.CertManager;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.PasswordGenerator;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
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