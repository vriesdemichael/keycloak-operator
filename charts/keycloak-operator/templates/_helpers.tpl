{{/*
Expand the name of the chart.
*/}}
{{- define "keycloak-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "keycloak-operator.fullname" -}}
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
{{- define "keycloak-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "keycloak-operator.labels" -}}
helm.sh/chart: {{ include "keycloak-operator.chart" . }}
{{ include "keycloak-operator.selectorLabels" . }}
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
{{- define "keycloak-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "keycloak-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end }}

{{/*
Create the name of the service account to use
Defaults to keycloak-operator-<namespace> to avoid conflicts
*/}}
{{- define "keycloak-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- printf "keycloak-operator-%s" (include "keycloak-operator.namespace" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Operator namespace
Uses Release namespace if specified, otherwise falls back to configured namespace
*/}}
{{- define "keycloak-operator.namespace" -}}
{{- if ne .Release.Namespace "default" -}}
{{- .Release.Namespace }}
{{- else -}}
{{- default "keycloak-system" .Values.namespace.name }}
{{- end -}}
{{- end }}

{{/*
Operator image
*/}}
{{- define "keycloak-operator.image" -}}
{{- $tag := .Values.operator.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.operator.image.repository $tag }}
{{- end }}

{{/*
Common annotations
*/}}
{{- define "keycloak-operator.annotations" -}}
{{- with .Values.commonAnnotations }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Operator instance ID for resource ownership tracking
Auto-generates: <release-name>-<namespace> if not explicitly set
*/}}
{{- define "keycloak-operator.instanceId" -}}
{{- if .Values.operator.instanceId }}
{{- .Values.operator.instanceId }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "keycloak-operator.namespace" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
