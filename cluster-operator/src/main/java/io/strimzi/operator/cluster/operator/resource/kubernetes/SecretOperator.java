/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package io.strimzi.operator.cluster.operator.resource.kubernetes;

import io.fabric8.kubernetes.api.model.DeletionPropagation;
import io.fabric8.kubernetes.api.model.LabelSelector;
import io.fabric8.kubernetes.api.model.ListOptions;
import io.fabric8.kubernetes.api.model.ObjectReference;
import io.fabric8.kubernetes.api.model.Secret;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.api.model.SecretList;
import io.fabric8.kubernetes.api.model.StatusDetails;
import io.fabric8.kubernetes.client.GracePeriodConfigurable;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.PropagationPolicyConfigurable;
import io.fabric8.kubernetes.client.Watch;
import io.fabric8.kubernetes.client.Watcher;
import io.fabric8.kubernetes.client.dsl.AnyNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Deletable;
import io.fabric8.kubernetes.client.dsl.FilterNested;
import io.fabric8.kubernetes.client.dsl.FilterWatchListDeletable;
import io.fabric8.kubernetes.client.dsl.Informable;
import io.fabric8.kubernetes.client.dsl.ItemWritableOperation;
import io.fabric8.kubernetes.client.dsl.MixedOperation;
import io.fabric8.kubernetes.client.dsl.NonNamespaceOperation;
import io.fabric8.kubernetes.client.dsl.Resource;
import io.fabric8.kubernetes.client.dsl.Watchable;
import io.fabric8.kubernetes.client.informers.ResourceEventHandler;
import io.fabric8.kubernetes.client.informers.SharedIndexInformer;
import io.strimzi.operator.common.Reconciliation;
import io.strimzi.operator.common.ReconciliationLogger;
import io.strimzi.operator.common.model.Ca;
import io.strimzi.operator.common.model.Labels;
import io.strimzi.operator.common.operator.resource.ReconcileResult;
import io.vertx.core.Future;
import io.vertx.core.Vertx;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * Operations for {@code Secret}s.
 */
public class SecretOperator extends
        AbstractNamespacedResourceOperator<KubernetesClient, Secret, SecretList, Resource<Secret>> {
    private static final ReconciliationLogger LOGGER = ReconciliationLogger
            .create(SecretOperator.class);
    private static final String KAFKA_CLUSTER_NAME_ENV = "MSFT_KAFKA_CLUSTER_NAME";
    private static final String[] CERT_SECRETS_SUFFIXES = new String[] {
        "clients-ca", "clients-ca-cert", "cluster-ca",
        "cluster-ca-cert", "cluster-operator-certs", "entity-topic-operator-certs",
        "entity-user-operator-certs", "kafka-brokers"};
    private static final String INIT_GENERATION = String.valueOf(Ca.INIT_GENERATION);
    private final HashMap<String, Secret> secrets;

    /**
     * Constructor
     *
     * @param vertx
     *               The Vertx instance
     * @param client
     *               The Kubernetes client
     */
    public SecretOperator(Vertx vertx, KubernetesClient client) {
        super(vertx, client, "Secret");
        secrets = new HashMap<>();
        var clusterName = System.getenv(KAFKA_CLUSTER_NAME_ENV);
        if (clusterName == null || clusterName.isBlank()) {
            throw new RuntimeException("missing env var: " + KAFKA_CLUSTER_NAME_ENV);
        }

        var generationAnnotations = Map.of(
                Ca.ANNO_STRIMZI_IO_CA_CERT_GENERATION, INIT_GENERATION,
                Ca.ANNO_STRIMZI_IO_CA_KEY_GENERATION, INIT_GENERATION,
                Ca.ANNO_STRIMZI_IO_CLIENTS_CA_CERT_GENERATION, INIT_GENERATION,
                Ca.ANNO_STRIMZI_IO_CLUSTER_CA_CERT_GENERATION, INIT_GENERATION,
                Ca.ANNO_STRIMZI_IO_CLUSTER_CA_KEY_GENERATION, INIT_GENERATION);

        for (var suffix : CERT_SECRETS_SUFFIXES) {
            String secretName = clusterName + "-" + suffix;
            var secret = new SecretBuilder()
                    .withNewMetadata()
                    .withName(secretName)
                    .withAnnotations(generationAnnotations)
                    .endMetadata()
                    .withType("Opaque")
                    .withData(new HashMap<>())
                    .build();
            this.secrets.put(secretName, secret);
        }
    }

    @Override
    public Secret get(String namespace, String name) {
        var secret = this.secrets.get(name);
        if (secret == null) {
            LOGGER.infoOp(String.format(
                    "unredirected secret: ns=%s, name=%s",
                    namespace,
                    name));
        }
        return secret;
    }

    @Override
    public Future<Secret> getAsync(String namespace, String name) {
        return Future.succeededFuture(this.get(namespace, name));
    }

    @Override
    public Future<List<Secret>> listAsync(String namespace, Labels selector) {
        List<Secret> list = new ArrayList<>(this.secrets.values());
        return Future.succeededFuture(list);
    }

    @Override
    public Future<List<Secret>> listAsync(String namespace, LabelSelector selector) {
        List<Secret> list = new ArrayList<>(this.secrets.values());
        return Future.succeededFuture(list);
    }

    @Override
    public Future<ReconcileResult<Secret>> reconcile(Reconciliation reconciliation,
            String namespace, String name, Secret desired) {
        return Future.succeededFuture(ReconcileResult.noop(desired));
    }

    @Override
    public Future<Void> deleteAsync(Reconciliation reconciliation, String namespace, String name,
            boolean cascading) {
        return Future.succeededFuture();
    }

    @Override
    protected MixedOperation<Secret, SecretList, Resource<Secret>> operation() {
        return new RedirectOperation();
    }

    private class RedirectOperation
            implements MixedOperation<Secret, SecretList, Resource<Secret>> {

        @Override
        public AnyNamespaceOperation<Secret, SecretList, Resource<Secret>> inAnyNamespace() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'inAnyNamespace'");
        }

        @Override
        public NonNamespaceOperation<Secret, SecretList, Resource<Secret>> inNamespace(
                String arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'inNamespace'");
        }

        @Override
        public Resource<Secret> withName(String arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withName'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public boolean delete(List<Secret> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'delete'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public ItemWritableOperation<Secret> dryRun() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'dryRun'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public ItemWritableOperation<Secret> dryRun(boolean arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'dryRun'");
        }

        @Override
        public Resource<Secret> load(InputStream arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'load'");
        }

        @Override
        public Resource<Secret> load(URL arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'load'");
        }

        @Override
        public Resource<Secret> load(File arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'load'");
        }

        @Override
        public Resource<Secret> load(String arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'load'");
        }

        @Override
        public Resource<Secret> resource(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'resource'");
        }

        @Override
        public Stream<Resource<Secret>> resources() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'resources'");
        }

        @Override
        public FilterNested<FilterWatchListDeletable<Secret, SecretList, Resource<Secret>>> withNewFilter() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withNewFilter'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withField(String arg0,
                String arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withField'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withFields(
                Map<String, String> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withFields'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withInvolvedObject(
                ObjectReference arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withInvolvedObject'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withLabel(String arg0,
                String arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLabel'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withLabelIn(
                String arg0, String... arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLabelIn'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withLabelNotIn(
                String arg0, String... arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLabelNotIn'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withLabelSelector(
                LabelSelector arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLabelSelector'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withLabelSelector(
                String arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLabelSelector'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withLabels(
                Map<String, String> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLabels'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withoutField(
                String arg0, String arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withoutField'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withoutFields(
                Map<String, String> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withoutFields'");
        }

        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withoutLabel(
                String arg0, String arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withoutLabel'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public FilterWatchListDeletable<Secret, SecretList, Resource<Secret>> withoutLabels(
                Map<String, String> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withoutLabels'");
        }

        @Override
        public SecretList list() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'list'");
        }

        @Override
        public SecretList list(ListOptions arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'list'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public SecretList list(Integer arg0, String arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'list'");
        }

        @Override
        public Watchable<Secret> withResourceVersion(String arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withResourceVersion'");
        }

        @Override
        public Watch watch(Watcher<Secret> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'watch'");
        }

        @Override
        public Watch watch(ListOptions arg0, Watcher<Secret> arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'watch'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Watch watch(String arg0, Watcher<Secret> arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'watch'");
        }

        @Override
        public Secret waitUntilCondition(Predicate<Secret> arg0, long arg1, TimeUnit arg2) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'waitUntilCondition'");
        }

        @Override
        public Secret waitUntilReady(long arg0, TimeUnit arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'waitUntilReady'");
        }

        @Override
        public PropagationPolicyConfigurable<? extends Deletable> withGracePeriod(long arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withGracePeriod'");
        }

        @Override
        public List<StatusDetails> delete() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'delete'");
        }

        @Override
        public Deletable withTimeout(long arg0, TimeUnit arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withTimeout'");
        }

        @Override
        public Deletable withTimeoutInMillis(long arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withTimeoutInMillis'");
        }

        @Override
        public GracePeriodConfigurable<? extends Deletable> withPropagationPolicy(
                DeletionPropagation arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withPropagationPolicy'");
        }

        @Override
        public SharedIndexInformer<Secret> inform(ResourceEventHandler<? super Secret> arg0,
                long arg1) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'inform'");
        }

        @Override
        public CompletableFuture<List<Secret>> informOnCondition(Predicate<List<Secret>> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'informOnCondition'");
        }

        @Override
        public SharedIndexInformer<Secret> runnableInformer(long arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'runnableInformer'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Informable<Secret> withIndexers(Map<String, Function<Secret, List<String>>> arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withIndexers'");
        }

        @Override
        public Informable<Secret> withLimit(Long arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'withLimit'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Secret create(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'create'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Secret createOrReplace(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'createOrReplace'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public List<StatusDetails> delete(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'delete'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Secret patchStatus(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'patchStatus'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Secret updateStatus(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'updateStatus'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Secret replace(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'replace'");
        }

        @SuppressWarnings("deprecation")
        @Override
        public Secret replaceStatus(Secret arg0) {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'replaceStatus'");
        }
    }
}