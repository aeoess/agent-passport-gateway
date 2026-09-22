{{- define "agent-passport-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agent-passport-gateway.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "agent-passport-gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agent-passport-gateway.labels" -}}
app.kubernetes.io/name: {{ include "agent-passport-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "agent-passport-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agent-passport-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
