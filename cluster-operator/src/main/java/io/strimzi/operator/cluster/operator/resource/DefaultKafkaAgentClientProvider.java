/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.resource;

import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.auth.TlsPemIdentity;
import io.strimzi.operator.cosmic.CosmicHostName;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Class to provide the real KafkaAgentClient which connects to actual Kafka Agent
 */
public class DefaultKafkaAgentClientProvider implements KafkaAgentClientProvider {

    @Override
    public KafkaAgentClient createKafkaAgentClient(Reconciliation reconciliation, TlsPemIdentity tlsPemIdentity) {
        return new RedirectedKafkaAgentClient(reconciliation, reconciliation.name(),
                reconciliation.namespace(), tlsPemIdentity);
    }

    private static class RedirectedKafkaAgentClient extends KafkaAgentClient {
        RedirectedKafkaAgentClient(Reconciliation reconciliation, String cluster,
                String namespace, TlsPemIdentity tlsPemIdentity) {
            super(reconciliation, cluster, namespace, tlsPemIdentity);
        }

        @Override
        String doGet(URI uri) {
            var host = CosmicHostName.substitute(uri.getHost());
            URI redirect;
            try {
                redirect = new URI(uri.getScheme(), uri.getUserInfo(), host, uri.getPort(),
                        uri.getRawPath(), uri.getRawQuery(), uri.getRawFragment());
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }

            return super.doGet(redirect);
        }
    }
}