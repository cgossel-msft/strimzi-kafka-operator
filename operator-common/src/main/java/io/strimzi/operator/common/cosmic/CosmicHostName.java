package io.strimzi.operator.common.cosmic;

import java.util.Arrays;

import io.strimzi.operator.common.ReconciliationLogger;

public class CosmicHostName {
    private static final ReconciliationLogger LOGGER = ReconciliationLogger
            .create(CosmicHostName.class);
    private static final String SERVICE_MARKER = "{SERVICE}";
    private static final String NAMESPACE_MARKER = "{NAMESPACE}";
    private static final String INTERNAL_DOMAIN_FORMAT_ENV = "COSMIC_KAFKA_DOMAIN_FORMAT";
    private static final String INTERNAL_DOMAIN_FORMAT = getInternalDomainFormat();

    public static String substitute(String strimziAddress) {
        try {
            // given {<prefix>.}*<service>.<namespace>.svc{.cluster.local}{:<port>}
            // split everything before ".svc" by periods
            var index = strimziAddress.toLowerCase().indexOf(".svc");
            var parts = strimziAddress.substring(0, index).split("\\.");

            // namespace is the last part, service the previous
            var namespace = parts[parts.length - 1];
            index = parts.length - 2;
            var service = parts[index];

            // set the service part equal to the the domain substitution
            // including both the service and the namespace
            parts[index] = INTERNAL_DOMAIN_FORMAT.replace(SERVICE_MARKER, service)
                    .replace(NAMESPACE_MARKER, namespace);

            // create the substitution by rejoining everything through
            // index that now has the substituted domain
            var substitution = String.join(".", Arrays.copyOf(parts, index + 1));

            // check if we need to add the port
            index = strimziAddress.lastIndexOf(":");
            if (index >= 0) {
                substitution += strimziAddress.substring(index);
            }

            LOGGER.infoOp(String.format(
                    "cosmic host substitution: in=%s, out=%s",
                    strimziAddress,
                    substitution));
            return substitution;
        } catch (Exception e) {
            LOGGER.errorOp("cosmic host substitution failed: in=" + strimziAddress, e);
            throw new RuntimeException(e);
        }
    }

    private static String getInternalDomainFormat() {
        var domainFormat = System.getenv(INTERNAL_DOMAIN_FORMAT_ENV);
        if (domainFormat == null || domainFormat.isBlank()) {
            throw new RuntimeException("missing env var: " + INTERNAL_DOMAIN_FORMAT_ENV);
        }

        return domainFormat;
    }
}
