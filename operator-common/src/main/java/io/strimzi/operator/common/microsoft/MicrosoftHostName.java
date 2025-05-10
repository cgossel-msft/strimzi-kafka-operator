/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.common.microsoft;

import io.strimzi.operator.common.ReconciliationLogger;

import java.util.Arrays;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Defines what kafka related host names look like in microsoft.
 */
public class MicrosoftHostName {
    private static final ReconciliationLogger LOGGER = ReconciliationLogger
            .create(MicrosoftHostName.class);
    private static final String SERVICE_MARKER = "{SERVICE}";
    private static final String NAMESPACE_MARKER = "{NAMESPACE}";
    private static final String INTERNAL_DOMAIN_FORMAT_ENV = "MSFT_KAFKA_DOMAIN_FORMAT";
    private static final String INTERNAL_DOMAIN_FORMAT = getInternalDomainFormat();
    private static final Pattern INTERNAL_DOMAIN_PATTERN = getInternalDomainRegex();

    /**
     * Substitute the host in the given address for the appropriate microsoft kafka
     * host.
     * 
     * @param strimziAddress the host to be substituted
     * @return the address with the subsitution
     */
    public static String substitute(String strimziAddress) {
        try {
            var matcher = INTERNAL_DOMAIN_PATTERN.matcher(strimziAddress);
            if (matcher.find()) {
                LOGGER.infoOp(String.format(
                        "microsoft host substitution unnecessary: in=%s",
                        strimziAddress));
                return strimziAddress;
            }

            // given {<prefix>.}*<service>.<namespace>{.svc{.cluster.local}}{:<port>}
            // split everything before ".svc" by periods
            var index = strimziAddress.toLowerCase(Locale.US).indexOf(".svc");
            var portIndex = strimziAddress.lastIndexOf(":");
            if (index < 0) {
                // if we did not find .svc, assume it is left out
                index = portIndex < 0 ? strimziAddress.length() : portIndex;
            }

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
            if (portIndex >= 0) {
                substitution += strimziAddress.substring(portIndex);
            }

            LOGGER.infoOp(String.format(
                    "microsoft host substitution: in=%s, out=%s",
                    strimziAddress,
                    substitution));
            return substitution;
        } catch (Exception e) {
            LOGGER.errorOp("microsoft host substitution failed: in=" + strimziAddress, e);
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

    private static Pattern getInternalDomainRegex() {
        var regex = INTERNAL_DOMAIN_FORMAT
                .replace(".", "\\.")
                .replace(SERVICE_MARKER, ".*")
                .replace(NAMESPACE_MARKER, ".*");
        if (!regex.startsWith(".*")) {
            regex = ".*" + regex;
        }

        regex += "(:[0-9]+)?$";
        return Pattern.compile(regex);
    }
}
