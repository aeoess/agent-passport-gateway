{{- define "aeoess-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aeoess-gateway.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "aeoess-gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aeoess-gateway.labels" -}}
app.kubernetes.io/name: {{ include "aeoess-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "aeoess-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aeoess-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
