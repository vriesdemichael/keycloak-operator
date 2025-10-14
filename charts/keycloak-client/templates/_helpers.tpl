{{/*
Expand the name of the chart.
*/}}
{{- define "keycloak-client.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "keycloak-client.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "keycloak-client.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keycloak-client.labels" -}}
helm.sh/chart: {{ include "keycloak-client.chart" . }}
{{ include "keycloak-client.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "keycloak-client.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keycloak-client.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Client ID
*/}}
{{- define "keycloak-client.clientId" -}}
{{- required "clientId is required" .Values.clientId }}
{{- end }}

{{/*
Client secret name
*/}}
{{- define "keycloak-client.secretName" -}}
{{- if .Values.secret.secretName }}
{{- .Values.secret.secretName }}
{{- else }}
{{- printf "%s-client-secret" (include "keycloak-client.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "keycloak-client.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}
