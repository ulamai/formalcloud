{{- define "formal-cloud-admission.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "formal-cloud-admission.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "formal-cloud-admission.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "formal-cloud-admission.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "formal-cloud-admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "formal-cloud-admission.selectorLabels" -}}
app.kubernetes.io/name: {{ include "formal-cloud-admission.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "formal-cloud-admission.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "formal-cloud-admission.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "formal-cloud-admission.policyConfigMapName" -}}
{{- if .Values.policy.configMapName -}}
{{- .Values.policy.configMapName -}}
{{- else -}}
{{- printf "%s-policies" (include "formal-cloud-admission.fullname" .) -}}
{{- end -}}
{{- end -}}
