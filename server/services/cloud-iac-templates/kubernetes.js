// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: Kubernetes (R3k C14)
//
// Universal. Produces deployment + service + pvc + (optional) secret
// YAML manifests. Secrets are sourced from the cluster's secret store;
// operators populate via kubectl create secret or via the provider's
// CSI Secret Store driver.
// ═══════════════════════════════════════════════════════════════════════════════

function render(snapshot, provider) {
  const deployment = [
    'apiVersion: apps/v1',
    'kind: Deployment',
    'metadata:',
    '  name: firealive',
    '  labels:',
    '    app: firealive',
    `    firealive.io/provider: ${provider}`,
    'spec:',
    '  replicas: 1',
    '  selector:',
    '    matchLabels:',
    '      app: firealive',
    '  template:',
    '    metadata:',
    '      labels:',
    '        app: firealive',
    '    spec:',
    '      containers:',
    '        - name: firealive',
    '          image: ghcr.io/petermancina/firealive:latest',
    '          imagePullPolicy: IfNotPresent',
    '          ports:',
    '            - containerPort: 3000',
    '              name: http',
    '          env:',
    '            - name: TIER1_ENCRYPTION_KEY',
    '              valueFrom:',
    '                secretKeyRef:',
    '                  name: firealive-secrets',
    '                  key: tier1_encryption_key',
    '            - name: JWT_SECRET',
    '              valueFrom:',
    '                secretKeyRef:',
    '                  name: firealive-secrets',
    '                  key: jwt_secret',
    '          volumeMounts:',
    '            - name: firealive-data',
    '              mountPath: /data',
    '          readinessProbe:',
    '            httpGet: { path: /health, port: 3000 }',
    '            initialDelaySeconds: 10',
    '            periodSeconds: 30',
    '          livenessProbe:',
    '            httpGet: { path: /health, port: 3000 }',
    '            initialDelaySeconds: 30',
    '            periodSeconds: 60',
    '          resources:',
    '            requests: { cpu: "500m", memory: "1Gi" }',
    '            limits:   { cpu: "2000m", memory: "4Gi" }',
    '      volumes:',
    '        - name: firealive-data',
    '          persistentVolumeClaim:',
    '            claimName: firealive-data',
    '',
    `# Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
  ].join('\n');

  const service = [
    'apiVersion: v1',
    'kind: Service',
    'metadata:',
    '  name: firealive',
    '  labels:',
    '    app: firealive',
    'spec:',
    '  type: ClusterIP',
    '  selector:',
    '    app: firealive',
    '  ports:',
    '    - name: http',
    '      port: 80',
    '      targetPort: 3000',
    '',
  ].join('\n');

  const pvc = [
    'apiVersion: v1',
    'kind: PersistentVolumeClaim',
    'metadata:',
    '  name: firealive-data',
    'spec:',
    '  accessModes: ["ReadWriteOnce"]',
    '  resources:',
    '    requests:',
    '      storage: 50Gi',
    '',
  ].join('\n');

  const secretExample = [
    '# Apply this AFTER replacing the placeholders with real values:',
    '#   kubectl create secret generic firealive-secrets \\',
    '#     --from-literal=tier1_encryption_key=<32-byte-hex> \\',
    '#     --from-literal=jwt_secret=<random-16+-chars>',
    '#',
    '# OR use a CSI Secret Store driver (e.g. secrets-store-csi-driver +',
    '# the provider-specific provider: AWS / Azure / GCP / Vault). The',
    '# CSI pattern is preferred for production since secrets stay in the',
    '# provider\'s managed store rather than as base64 in cluster etcd.',
    '#',
    'apiVersion: v1',
    'kind: Secret',
    'metadata:',
    '  name: firealive-secrets',
    'type: Opaque',
    'stringData:',
    '  tier1_encryption_key: REPLACE_WITH_32_BYTE_HEX',
    '  jwt_secret: REPLACE_WITH_16+_RANDOM_CHARS',
    '',
  ].join('\n');

  return {
    files: [
      { path: 'firealive-deployment.yaml', content: deployment },
      { path: 'firealive-service.yaml', content: service },
      { path: 'firealive-pvc.yaml', content: pvc },
      { path: 'firealive-secret.example.yaml', content: secretExample },
    ],
  };
}

module.exports = { render };
