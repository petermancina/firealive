// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Cloud & IaC Templates: Helm Chart (R3k C14)
//
// Universal. Produces a Helm chart directory structure with Chart.yaml,
// values.yaml, and the core templates/. Operators run `helm install
// firealive ./firealive`.
// ═══════════════════════════════════════════════════════════════════════════════

function render(snapshot, provider) {
  const chart = [
    'apiVersion: v2',
    'name: firealive',
    'description: FireAlive SOC analyst wellbeing platform',
    'type: application',
    `version: ${snapshot.version.version === 'unknown' ? '0.1.0' : snapshot.version.version}`,
    `appVersion: "${snapshot.version.version}"`,
    `# Provider target at generation: ${provider}`,
    '',
  ].join('\n');

  const values = [
    `# values.yaml for FireAlive Helm chart (provider: ${provider})`,
    `# Snapshot at generation: users=${snapshot.users.total}, db_size_bytes=${snapshot.data.db_size_bytes}`,
    '',
    'image:',
    '  repository: ghcr.io/petermancina/firealive',
    '  tag: latest',
    '  pullPolicy: IfNotPresent',
    '',
    'replicaCount: 1',
    '',
    'service:',
    '  type: ClusterIP',
    '  port: 80',
    '',
    'persistence:',
    '  enabled: true',
    '  size: 50Gi',
    '  storageClass: ""',
    '',
    'resources:',
    '  requests:',
    '    cpu: 500m',
    '    memory: 1Gi',
    '  limits:',
    '    cpu: 2000m',
    '    memory: 4Gi',
    '',
    'secrets:',
    '  # Populate via --set-string or via an external secret store (CSI driver).',
    '  tier1EncryptionKey: ""',
    '  jwtSecret: ""',
    '',
  ].join('\n');

  const helpers = [
    '{{/* Common labels */}}',
    '{{- define "firealive.labels" -}}',
    'app.kubernetes.io/name: firealive',
    'app.kubernetes.io/instance: {{ .Release.Name }}',
    'app.kubernetes.io/managed-by: {{ .Release.Service }}',
    'helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}',
    '{{- end -}}',
    '',
  ].join('\n');

  const deployment = [
    'apiVersion: apps/v1',
    'kind: Deployment',
    'metadata:',
    '  name: {{ .Release.Name }}',
    '  labels: {{- include "firealive.labels" . | nindent 4 }}',
    'spec:',
    '  replicas: {{ .Values.replicaCount }}',
    '  selector:',
    '    matchLabels:',
    '      app.kubernetes.io/name: firealive',
    '      app.kubernetes.io/instance: {{ .Release.Name }}',
    '  template:',
    '    metadata:',
    '      labels: {{- include "firealive.labels" . | nindent 8 }}',
    '    spec:',
    '      containers:',
    '        - name: firealive',
    '          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"',
    '          imagePullPolicy: {{ .Values.image.pullPolicy }}',
    '          ports:',
    '            - containerPort: 3000',
    '          env:',
    '            - name: TIER1_ENCRYPTION_KEY',
    '              valueFrom:',
    '                secretKeyRef:',
    '                  name: {{ .Release.Name }}-secrets',
    '                  key: tier1_encryption_key',
    '            - name: JWT_SECRET',
    '              valueFrom:',
    '                secretKeyRef:',
    '                  name: {{ .Release.Name }}-secrets',
    '                  key: jwt_secret',
    '          volumeMounts:',
    '            - name: data',
    '              mountPath: /data',
    '          resources: {{- toYaml .Values.resources | nindent 12 }}',
    '      volumes:',
    '        - name: data',
    '          persistentVolumeClaim:',
    '            claimName: {{ .Release.Name }}-data',
    '',
  ].join('\n');

  const service = [
    'apiVersion: v1',
    'kind: Service',
    'metadata:',
    '  name: {{ .Release.Name }}',
    '  labels: {{- include "firealive.labels" . | nindent 4 }}',
    'spec:',
    '  type: {{ .Values.service.type }}',
    '  selector:',
    '    app.kubernetes.io/name: firealive',
    '    app.kubernetes.io/instance: {{ .Release.Name }}',
    '  ports:',
    '    - port: {{ .Values.service.port }}',
    '      targetPort: 3000',
    '',
  ].join('\n');

  const pvc = [
    '{{- if .Values.persistence.enabled -}}',
    'apiVersion: v1',
    'kind: PersistentVolumeClaim',
    'metadata:',
    '  name: {{ .Release.Name }}-data',
    'spec:',
    '  accessModes: [ReadWriteOnce]',
    '  resources:',
    '    requests:',
    '      storage: {{ .Values.persistence.size }}',
    '  {{- if .Values.persistence.storageClass }}',
    '  storageClassName: {{ .Values.persistence.storageClass | quote }}',
    '  {{- end }}',
    '{{- end -}}',
    '',
  ].join('\n');

  const secret = [
    'apiVersion: v1',
    'kind: Secret',
    'metadata:',
    '  name: {{ .Release.Name }}-secrets',
    'type: Opaque',
    'stringData:',
    '  tier1_encryption_key: {{ .Values.secrets.tier1EncryptionKey | quote }}',
    '  jwt_secret: {{ .Values.secrets.jwtSecret | quote }}',
    '',
  ].join('\n');

  return {
    files: [
      { path: 'Chart.yaml', content: chart },
      { path: 'values.yaml', content: values },
      { path: 'templates/_helpers.tpl', content: helpers },
      { path: 'templates/deployment.yaml', content: deployment },
      { path: 'templates/service.yaml', content: service },
      { path: 'templates/pvc.yaml', content: pvc },
      { path: 'templates/secret.yaml', content: secret },
    ],
  };
}

module.exports = { render };
