{{- define "mcp-oauth-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcp-oauth-proxy.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "mcp-oauth-proxy.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "mcp-oauth-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "mcp-oauth-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-oauth-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mcp-oauth-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mcp-oauth-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "mcp-oauth-proxy.policyConfigMapName" -}}
{{- if .Values.authorization.existingPolicyConfigMap -}}
{{- .Values.authorization.existingPolicyConfigMap -}}
{{- else -}}
{{- printf "%s-policy" (include "mcp-oauth-proxy.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* The policy lives in its own ConfigMap when an existing one is named, or when
the operator asked for the rules to be split out of the main configuration. */}}
{{- define "mcp-oauth-proxy.usePolicyFile" -}}
{{- if .Values.authorization.existingPolicyConfigMap -}}true
{{- else if and .Values.authorization.separatePolicyConfigMap .Values.authorization.policy.rules -}}true
{{- end -}}
{{- end -}}

{{/* Fail fast on configuration that would make the proxy insecure or unbootable. */}}
{{- define "mcp-oauth-proxy.validate" -}}
{{- if not .Values.authorization.oauth2.resource -}}
{{- fail "authorization.oauth2.resource is required and must be the canonical public https URI of the MCP endpoint" -}}
{{- end -}}
{{- if not .Values.authorization.oauth2.oauth2Client -}}
{{- fail "authorization.oauth2.oauth2Client must list at least one trusted Entra ID application registration" -}}
{{- end -}}
{{- range $i, $c := .Values.authorization.oauth2.oauth2Client -}}
{{- if not $c.tenantID -}}
{{- fail (printf "authorization.oauth2.oauth2Client[%d].tenantID is required" $i) -}}
{{- end -}}
{{- if not $c.clientID -}}
{{- fail (printf "authorization.oauth2.oauth2Client[%d].clientID is required" $i) -}}
{{- end -}}
{{- end -}}
{{/* Group membership is the only gate, so an empty allow list would let every
user in the tenant through. The proxy also rejects this, but failing at render
time keeps a bad change from ever reaching the cluster. */}}
{{- if not .Values.authorization.oauth2.allowGroups -}}
{{- fail "authorization.oauth2.allowGroups is required; without it every authenticated user in the tenant could reach the MCP server" -}}
{{- end -}}
{{- if and .Values.authorization.oauth2.allowAppOnly (not .Values.authorization.oauth2.allowRoles) -}}
{{- fail "authorization.oauth2.allowRoles is required when allowAppOnly is true; app-only callers have no group membership to check" -}}
{{- end -}}
{{- if not (has .Values.graphCredential.type (list "federated" "secret")) -}}
{{- fail "graphCredential.type must be federated or secret" -}}
{{- end -}}
{{- $flow := default "app_permission" (default (dict) .Values.authorization.oauth2.graph).flow -}}
{{- if not (has $flow (list "app_permission" "obo")) -}}
{{- fail (printf "authorization.oauth2.graph.flow must be app_permission or obo, got %q" $flow) -}}
{{- end -}}
{{/* The two flows constrain the credential in opposite ways, so the checks
below differ. app_permission uses one app-only credential, which can only read
its own directory. obo exchanges the caller's token at the caller's own tenant,
so any tenant works, but only the application the token was issued for may
perform the exchange. */}}
{{- if eq $flow "obo" -}}
{{- range $i, $c := .Values.authorization.oauth2.oauth2Client -}}
{{- if ne (default "msgraph" $c.groupsSource) "jwt" -}}
{{- if and $.Values.graphCredential.clientId (ne $c.clientID $.Values.graphCredential.clientId) -}}
{{- fail (printf "graphCredential.clientId %s differs from authorization.oauth2.oauth2Client[%d].clientID %s; the On-Behalf-Of exchange can only be performed by the application the inbound token was issued for, so leave graphCredential.clientId empty or set it to that client id" $.Values.graphCredential.clientId $i $c.clientID) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- else -}}
{{- if not .Values.graphCredential.clientId -}}
{{- fail "graphCredential.clientId is required; it is the identity that holds the GroupMember.Read.All application permission" -}}
{{- end -}}
{{- $credTenant := default (first .Values.authorization.oauth2.oauth2Client).tenantID .Values.graphCredential.tenantId -}}
{{- range $i, $c := .Values.authorization.oauth2.oauth2Client -}}
{{- if and (ne (default "msgraph" $c.groupsSource) "jwt") (ne $c.tenantID $credTenant) -}}
{{- fail (printf "authorization.oauth2.oauth2Client[%d].tenantID %s differs from the Graph credential's tenant %s; one app-only credential cannot read another tenant's directory, so set groupsSource: jwt for that application, or use graph.flow: obo which exchanges at the caller's tenant" $i $c.tenantID $credTenant) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.graphCredential.type "secret" -}}
{{- if and (not .Values.graphCredential.secret.existingSecret) (not .Values.graphCredential.secret.create) -}}
{{- fail "graphCredential.secret.existingSecret or graphCredential.secret.create is required when graphCredential.type is secret" -}}
{{- end -}}
{{- if and .Values.graphCredential.secret.create (not .Values.graphCredential.secret.value) -}}
{{- fail "graphCredential.secret.value is required when graphCredential.secret.create is true" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.authorization.oauth2.dynamicClientRegistration.enabled (not .Values.authorization.oauth2.dynamicClientRegistration.staticClientID) -}}
{{- fail "authorization.oauth2.dynamicClientRegistration.staticClientID is required when the shim is enabled" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "ingress.host is required when the ingress is enabled" -}}
{{- end -}}
{{- end -}}

{{/*
Builds the authorization.oauth2 block, attaching the chart-level Graph
credential. There is a single credential for the whole deployment: under
app_permission it is the identity the proxy calls Graph as, and under obo it is
the application that exchanges the caller's token.
*/}}
{{- define "mcp-oauth-proxy.oauth2" -}}
{{- $oauth2 := deepCopy .Values.authorization.oauth2 -}}
{{- $cred := .Values.graphCredential -}}
{{- $graph := default (dict) $oauth2.graph -}}
{{- $c := dict "type" $cred.type -}}
{{- with $cred.clientId }}{{- $_ := set $c "clientID" . }}{{- end -}}
{{/* Under obo the exchange runs at the caller's tenant, so pinning a tenant on
the credential would be misleading in the rendered config. */}}
{{- if ne (default "app_permission" $graph.flow) "obo" -}}
{{- $_ := set $c "tenantID" (default (first $oauth2.oauth2Client).tenantID $cred.tenantId) -}}
{{- end -}}
{{- if eq $cred.type "secret" }}{{- $_ := set $c "clientSecretEnv" "GRAPH_CLIENT_SECRET" }}{{- end -}}
{{- $_ := set $graph "credential" $c -}}
{{- $_ := set $oauth2 "graph" $graph -}}
{{- if not $oauth2.userLoginTransformer }}{{- $_ := unset $oauth2 "userLoginTransformer" }}{{- end -}}
{{- if not $oauth2.allowAppOnly }}{{- $_ := unset $oauth2 "allowRoles" }}{{- end -}}
{{- range $k, $v := $oauth2 }}{{- if not $v }}{{- if not (kindIs "bool" $v) }}{{- $_ := unset $oauth2 $k }}{{- end }}{{- end }}{{- end -}}
{{- toYaml $oauth2 -}}
{{- end -}}

{{- define "mcp-oauth-proxy.graphSecretName" -}}
{{- if .Values.graphCredential.secret.existingSecret -}}
{{- .Values.graphCredential.secret.existingSecret -}}
{{- else -}}
{{- printf "%s-graph" (include "mcp-oauth-proxy.fullname" .) -}}
{{- end -}}
{{- end -}}
