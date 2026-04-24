{{/* vim: set filetype=mustache: */}}

{{/*
Resolve the release's fullname. Used as the prefix for every
resource so two releases in the same namespace don't collide.
*/}}
{{- define "siphon.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := .Chart.Name }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Per-component fullname. `component` is the sub-chart label
("api" / "fs" / "ui" / "authelia" / "nginx").
*/}}
{{- define "siphon.componentName" -}}
{{- printf "%s-%s" (include "siphon.fullname" .root) .component | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
chart label (chart-name + chart-version).
*/}}
{{- define "siphon.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Labels applied to every resource. `component` optional; when
passed, lands as `app.kubernetes.io/component`.
*/}}
{{- define "siphon.labels" -}}
helm.sh/chart: {{ include "siphon.chart" .root }}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: siphon
{{- with .component }}
app.kubernetes.io/component: {{ . }}
{{- end }}
{{- with .root.Values.global.commonLabels }}
{{- toYaml . | nindent 0 }}
{{- end }}
{{- end }}

{{/*
Selector labels for Deployment / Service matching. Minimal set
so adding labels above doesn't break upgrades.
*/}}
{{- define "siphon.selectorLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Compose a full image reference. Accepts dict with `registry`,
`repository`, `tag`, `pullPolicy` — per-component values. Falls
back to chart-default tag (appVersion) and global.imageRegistry.
*/}}
{{- define "siphon.image" -}}
{{- $reg := default .root.Values.global.imageRegistry .image.registry -}}
{{- $repo := .image.repository -}}
{{- $tag := default .root.Chart.AppVersion .image.tag -}}
{{- if $reg }}
{{- printf "%s/%s:%s" $reg $repo $tag }}
{{- else }}
{{- printf "%s:%s" $repo $tag }}
{{- end }}
{{- end }}

{{/*
Per-component pod annotations. Folds in global commonAnnotations
and optionally the Linkerd inject annotation.
*/}}
{{- define "siphon.podAnnotations" -}}
{{- with .root.Values.global.commonAnnotations }}
{{- toYaml . }}
{{- end }}
{{- if .root.Values.global.linkerd.enabled }}
linkerd.io/inject: enabled
{{- end }}
{{- end }}

{{/*
Image pull secrets — union of global and (optional) component.
*/}}
{{- define "siphon.imagePullSecrets" -}}
{{- $all := list -}}
{{- with .root.Values.global.imagePullSecrets }}
{{- range . }}
{{- $all = append $all . }}
{{- end }}
{{- end }}
{{- if $all }}
{{- toYaml $all }}
{{- end }}
{{- end }}
