{{/* The release's name for its resources. */}}
{{- define "clavia.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "clavia.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "clavia.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "clavia.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/* Clavia's settings, for every container that runs the application: the pods, the Job, the CronJobs. */}}
{{- define "clavia.env" -}}
- name: CLAVIA_ROOT_DOMAIN
  value: {{ required "rootDomain is required" .Values.rootDomain | quote }}
{{- range $name, $value := .Values.env }}
{{- if ne $name "CLAVIA_ROOT_DOMAIN" }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "clavia.envFrom" -}}
- secretRef:
    name: {{ required "existingSecret is required: a Secret with Clavia's secret settings" .Values.existingSecret }}
{{- end -}}

{{/* A container running one bin/clavia command, for the Job and the CronJobs. */}}
{{- define "clavia.commandContainer" -}}
- name: clavia
  image: {{ include "clavia.image" .root }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  command: ["php", "bin/clavia", {{ .command | quote }}]
  env:
    {{- include "clavia.env" .root | nindent 4 }}
  envFrom:
    {{- include "clavia.envFrom" .root | nindent 4 }}
  {{- with .root.Values.php.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end -}}
