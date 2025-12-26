#!/usr/bin/env python3
"""
Extract validatable schema references from documentation.

This module extracts:
1. Helm --set flags from bash/shell code blocks
2. YAML blocks that look like Helm values
3. YAML blocks that are Kubernetes CRs
4. Inline Helm values in ArgoCD Applications

Each extracted reference includes context detection to determine
what schema it should be validated against.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class ReferenceContext(Enum):
    """Context for a documentation reference."""

    HELM_SET = "helm-set"  # --set flag in helm command
    HELM_VALUES = "helm-values"  # YAML that looks like values.yaml
    CR_KEYCLOAK = "cr-keycloak"  # Keycloak CR instance
    CR_REALM = "cr-realm"  # KeycloakRealm CR instance
    CR_CLIENT = "cr-client"  # KeycloakClient CR instance
    K8S_OTHER = "k8s-other"  # Other K8s resource (Ingress, Secret, etc.)
    UNKNOWN = "unknown"  # Cannot determine context


@dataclass
class ExtractedReference:
    """A single extracted reference from documentation."""

    file: Path
    line: int
    context: ReferenceContext
    content: dict[str, Any] | str  # Parsed YAML or --set key path
    raw: str  # Original text for error messages
    surrounding_text: str = ""  # Text before/after for context hints
    parent_path: str = ""  # Inferred parent path for partial snippets
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractionResult:
    """Result of extracting references from a file."""

    file: Path
    references: list[ExtractedReference]
    skipped: list[tuple[int, str, str]]  # (line, reason, raw_content)
    errors: list[tuple[int, str]]  # (line, error_message)


# Known top-level keys in values.yaml for context detection
HELM_VALUES_ROOT_KEYS = {
    "operator",
    "namespace",
    "serviceAccount",
    "rbac",
    "crds",
    "monitoring",
    "keycloak",
    "extraManifests",
    "commonLabels",
    "commonAnnotations",
    "webhooks",
}

# Keys that indicate this is a Helm values snippet (not a CR)
HELM_VALUES_INDICATORS = {
    "replicaCount",
    "image.repository",
    "image.pullPolicy",
    "image.tag",
    "imagePullSecrets",
    "resources.limits",
    "resources.requests",
    "nodeSelector",
    "tolerations",
    "affinity",
    "enabled",  # Common in Helm charts
}

# Keycloak CRD API versions
KEYCLOAK_API_VERSIONS = {
    "vriesdemichael.github.io/v1",
    "vriesdemichael.github.io/v1alpha1",
    "vriesdemichael.github.io/v1beta1",
}


def extract_yaml_blocks(content: str) -> list[tuple[int, str, str]]:
    """
    Extract YAML code blocks from markdown content.

    Returns:
        List of (line_number, yaml_content, language_hint)
    """
    blocks = []

    # Pattern for fenced code blocks with optional language
    # Matches ```yaml, ```yml, ``` (no lang), ```bash (for heredocs)
    pattern = r"^```(\w*)\s*\n(.*?)^```"

    for match in re.finditer(pattern, content, re.MULTILINE | re.DOTALL):
        lang = match.group(1).lower()
        block_content = match.group(2)

        # Calculate line number
        line_no = content[: match.start()].count("\n") + 1

        # Only process YAML-like blocks
        if lang in ("yaml", "yml", ""):
            blocks.append((line_no, block_content, lang))
        elif lang in ("bash", "shell", "sh"):
            # Check for heredocs containing YAML
            heredoc_yamls = extract_heredoc_yaml(block_content)
            for offset, heredoc_content in heredoc_yamls:
                blocks.append((line_no + offset, heredoc_content, "yaml-heredoc"))

    return blocks


def extract_heredoc_yaml(bash_content: str) -> list[tuple[int, str]]:
    """
    Extract YAML from heredocs in bash code.

    Patterns:
    - cat << 'EOF'
    - cat << EOF
    - cat <<-EOF
    - kubectl apply -f - << EOF

    Returns:
        List of (line_offset, yaml_content)
    """
    results = []

    # Match heredoc patterns
    pattern = r"<<-?\s*['\"]?(\w+)['\"]?\s*\n(.*?)^\1"

    for match in re.finditer(pattern, bash_content, re.MULTILINE | re.DOTALL):
        heredoc_content = match.group(2)
        line_offset = bash_content[: match.start()].count("\n")

        # Check if it looks like YAML (has colons, indentation)
        if ":" in heredoc_content and re.search(
            r"^\s+\w+:", heredoc_content, re.MULTILINE
        ):
            results.append((line_offset, heredoc_content))

    return results


def extract_helm_set_flags(content: str, file_path: Path) -> list[ExtractedReference]:
    """
    Extract --set flags from helm commands in documentation.

    Patterns matched:
    - --set key=value
    - --set key="value"
    - --set 'key=value'
    - --set key.subkey=value
    - --set-string key=value
    - --set 'arr={v1,v2}'
    """
    references = []

    # Find all code blocks that might contain helm commands
    code_block_pattern = r"^```(?:bash|shell|sh)?\s*\n(.*?)^```"

    for block_match in re.finditer(
        code_block_pattern, content, re.MULTILINE | re.DOTALL
    ):
        block_content = block_match.group(1)
        block_start_line = content[: block_match.start()].count("\n") + 1

        # Find helm commands
        helm_pattern = r"helm\s+(?:install|upgrade|template)[^\n]*"

        for helm_match in re.finditer(helm_pattern, block_content):
            helm_cmd = helm_match.group(0)
            cmd_line = block_start_line + block_content[: helm_match.start()].count(
                "\n"
            )

            # Handle line continuations
            full_cmd = helm_cmd
            remaining = block_content[helm_match.end() :]
            while remaining.startswith(" \\\n") or full_cmd.rstrip().endswith("\\"):
                next_line_match = re.match(r"\s*\\?\n\s*([^\n]+)", remaining)
                if next_line_match:
                    full_cmd += " " + next_line_match.group(1).strip()
                    remaining = remaining[next_line_match.end() :]
                else:
                    break

            # Extract chart name from the helm command
            # Patterns:
            # - helm install <release> <chart>
            # - helm install <release> oci://registry/chart
            # - helm upgrade <release> <chart>
            chart_name = _extract_chart_name(full_cmd)

            # Extract --set flags
            set_patterns = [
                r"--set(?:-string)?\s+['\"]?([a-zA-Z][a-zA-Z0-9._-]*)=([^'\"\s]+)['\"]?",
                r"--set(?:-string)?\s+'([a-zA-Z][a-zA-Z0-9._-]*)=([^']+)'",
                r'--set(?:-string)?\s+"([a-zA-Z][a-zA-Z0-9._-]*)=([^"]+)"',
            ]

            for pattern in set_patterns:
                for set_match in re.finditer(pattern, full_cmd):
                    key = set_match.group(1)
                    value = set_match.group(2)

                    references.append(
                        ExtractedReference(
                            file=file_path,
                            line=cmd_line,
                            context=ReferenceContext.HELM_SET,
                            content=key,
                            raw=f"--set {key}={value}",
                            surrounding_text=full_cmd[:200],
                            metadata={
                                "value": value,
                                "full_command": full_cmd[:500],
                                "chart_name": chart_name,
                            },
                        )
                    )

    return references


def _extract_chart_name(helm_cmd: str) -> str:
    """
    Extract the chart name from a helm install/upgrade command.

    Examples:
    - helm install keycloak-operator oci://ghcr.io/vriesdemichael/charts/keycloak-operator
      -> keycloak-operator
    - helm install my-realm keycloak-operator/keycloak-realm
      -> keycloak-realm
    - helm install cnpg cloudnative-pg/cloudnative-pg
      -> cloudnative-pg
    - helm install keycloak-operator ./charts/keycloak-operator
      -> keycloak-operator
    """
    # Remove common flags that might appear before the chart name
    cmd = helm_cmd

    # Pattern to match helm install/upgrade <release-name> <chart>
    # The chart can be:
    # - oci://registry/path/chart-name
    # - repo/chart-name
    # - ./local/path/chart-name
    # - chart-name (if repo is added)

    # First, try to find OCI registry pattern
    oci_match = re.search(r"oci://[^\s]+/([a-zA-Z0-9_-]+)", cmd)
    if oci_match:
        return oci_match.group(1)

    # Try repo/chart pattern
    repo_chart_match = re.search(r"\s([a-zA-Z0-9_-]+)/([a-zA-Z0-9_-]+)(?:\s|$)", cmd)
    if repo_chart_match:
        return repo_chart_match.group(2)

    # Try local path pattern
    local_path_match = re.search(r"\./[^\s]*/([a-zA-Z0-9_-]+)(?:\s|$)", cmd)
    if local_path_match:
        return local_path_match.group(1)

    # Try to extract from helm install <release> <chart> pattern
    # where chart is just a name (repo already added)
    install_match = re.search(
        r"helm\s+(?:install|upgrade)\s+[a-zA-Z0-9_-]+\s+([a-zA-Z0-9_-]+)(?:\s|$)", cmd
    )
    if install_match:
        chart = install_match.group(1)
        # Filter out common flags that might be captured
        if chart not in ("--set", "--namespace", "--create-namespace", "--wait", "-n"):
            return chart

    return "unknown"


def detect_yaml_context(
    parsed: dict[str, Any], raw: str, surrounding_text: str
) -> tuple[ReferenceContext, str]:
    """
    Detect the context of a YAML block.

    Returns:
        (context, parent_path) - context type and inferred parent path
    """
    # Check if it's a Kubernetes resource (has apiVersion and kind)
    if "apiVersion" in parsed and "kind" in parsed:
        api_version = parsed.get("apiVersion", "")
        kind = parsed.get("kind", "")

        if api_version in KEYCLOAK_API_VERSIONS:
            kind_to_context = {
                "Keycloak": ReferenceContext.CR_KEYCLOAK,
                "KeycloakRealm": ReferenceContext.CR_REALM,
                "KeycloakClient": ReferenceContext.CR_CLIENT,
            }
            if kind in kind_to_context:
                return kind_to_context[kind], ""

        # Other K8s resources
        return ReferenceContext.K8S_OTHER, ""

    # Check if it's a status example (read-only, not user configurable)
    if "status" in parsed and len(parsed) == 1:
        return ReferenceContext.K8S_OTHER, ""  # Skip status examples

    # Check if it's application config (Spring, etc.) - not our concern
    if "spring" in parsed or "quarkus" in parsed or "micronaut" in parsed:
        return ReferenceContext.K8S_OTHER, ""

    # Check if it looks like an annotation example (keys with slashes)
    if all("/" in str(k) or "." in str(k) for k in parsed):
        # Likely annotation or label examples
        return ReferenceContext.K8S_OTHER, ""

    # Check for Prometheus rule groups
    if "groups" in parsed and isinstance(parsed.get("groups"), list):
        groups = parsed["groups"]
        if groups and isinstance(groups[0], dict) and "rules" in groups[0]:
            return ReferenceContext.K8S_OTHER, ""

    # Check for CNPG/PostgreSQL specific config (not our CRD)
    cnpg_keys = {
        "bootstrap",
        "backup",
        "postgresql",
        "certificates",
        "affinity",
        "retentionPolicy",
    }
    if parsed.keys() & cnpg_keys and "spec" not in parsed:
        return ReferenceContext.K8S_OTHER, ""

    # Check if top-level keys match Helm values structure
    top_keys = set(parsed.keys())

    if top_keys & HELM_VALUES_ROOT_KEYS:
        return ReferenceContext.HELM_VALUES, ""

    # Check surrounding text for context hints
    text_lower = surrounding_text.lower()

    if any(
        hint in text_lower
        for hint in [
            "values.yaml",
            "values file",
            "helm values",
            "helm install",
            "helm upgrade",
        ]
    ):
        return ReferenceContext.HELM_VALUES, ""

    # Check for partial CRD spec with 'spec' key
    if "spec" in parsed and len(parsed) == 1:
        spec_content = parsed["spec"]
        if isinstance(spec_content, dict):
            # Determine which CRD based on spec fields
            spec_keys = set(spec_content.keys())

            # Check for CNPG-specific spec keys first
            cnpg_spec_keys = {
                "certificates",
                "bootstrap",
                "backup",
                "postgresql",
                "monitoring",
                "superuserSecret",
                "enableSuperuserAccess",
            }
            if spec_keys & cnpg_spec_keys and not (
                spec_keys & {"database", "replicas", "image"}
            ):
                return ReferenceContext.K8S_OTHER, ""

            # Keycloak CRD indicators (expanded)
            keycloak_indicators = {
                "database",
                "replicas",
                "image",
                "ingress",
                "tls",
                "service",
                "resources",
                "env",
                "jvmOptions",
                "serviceAccount",
                "startupProbe",
                "livenessProbe",
                "readinessProbe",
                "podSecurityContext",
                "securityContext",
                "realmCapacity",
            }
            if spec_keys & keycloak_indicators:
                return ReferenceContext.CR_KEYCLOAK, ""

            # KeycloakRealm CRD indicators (expanded)
            realm_indicators = {
                "realmName",
                "instanceRef",
                "operatorRef",
                "displayName",
                "security",
                "themes",
                "smtpServer",
                "smtp",
                "tokenSettings",
                "clientAuthorizationGrants",
                "authenticationFlows",
                "userFederation",
                "clientScopes",
                "eventsConfig",
                "localization",
                "identityProviders",
                "roles",
                "groups",
                "attributes",
            }
            if spec_keys & realm_indicators:
                return ReferenceContext.CR_REALM, ""

            # KeycloakClient CRD indicators (expanded)
            client_indicators = {
                "clientId",
                "clientName",
                "realmRef",
                "publicClient",
                "bearerOnly",
                "redirectUris",
                "webOrigins",
                "protocolMappers",
                "clientRoles",
                "settings",
                "authenticationFlows",
                "manageSecret",
                "secretName",
                "description",
                "attributes",
            }
            if spec_keys & client_indicators:
                return ReferenceContext.CR_CLIENT, ""

    # Partial realm spec snippets (no 'spec' wrapper)
    realm_direct_keys = {
        "smtp",
        "smtpServer",
        "identityProviders",
        "userFederation",
        "clientScopes",
        "authenticationFlows",
        "eventsConfig",
        "localization",
    }
    if parsed.keys() & realm_direct_keys:
        return ReferenceContext.CR_REALM, "spec"

    # Partial client spec snippets - extended list of client-specific fields
    client_spec_keys = {
        "protocolMappers",
        "clientRoles",
        "clientId",
        "redirectUris",
        "webOrigins",
        "postLogoutRedirectUris",
        "baseUrl",
        "rootUrl",
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "serviceAccountRoles",
        "bearerOnly",
        "publicClient",
        "defaultClientScopes",
        "optionalClientScopes",
        "settings",  # Contains pkceCodeChallengeMethod, etc.
    }
    if parsed.keys() & client_spec_keys:
        return ReferenceContext.CR_CLIENT, "spec"

    # Partial realm spec snippets - extended list of realm-specific fields
    realm_spec_keys = {
        "realmName",
        "displayName",
        "operatorRef",
        "themes",
        "tokenSettings",
        "security",
        "attributes",
    }
    if parsed.keys() & realm_spec_keys:
        return ReferenceContext.CR_REALM, "spec"

    # Config snippet (nested under config key, common in IdP examples)
    # Check file path and surrounding text for IdP context
    idp_keywords = (
        "identity" in text_lower
        or "provider" in text_lower
        or "idp" in text_lower
        or "google" in text_lower
        or "azure" in text_lower
        or "saml" in text_lower
        or "oidc" in text_lower
        or "domain" in text_lower
    )
    if "config" in parsed and len(parsed) == 1 and idp_keywords:
        return ReferenceContext.CR_REALM, "spec.identityProviders[].config"

    # Check if this looks like a partial Helm values snippet
    # (has nested structure typical of values.yaml sections)
    if any(
        k in parsed
        for k in ["enabled", "image", "resources", "nodeSelector", "tolerations"]
    ):
        return ReferenceContext.HELM_VALUES, ""

    # Check for env array (could be Helm values or K8s pod spec)
    if "env" in parsed and isinstance(parsed.get("env"), list):
        # If env items have 'name' and 'value', it's a K8s env spec fragment
        env_list = parsed["env"]
        if env_list and isinstance(env_list[0], dict) and "name" in env_list[0]:
            return ReferenceContext.K8S_OTHER, ""

    # Service/ingress snippets without context
    if parsed.keys() == {"service"} or parsed.keys() == {"ingress"}:
        # Could be either Helm or partial CRD - check surrounding text more carefully
        if "keycloak" in text_lower and "cr" in text_lower:
            return ReferenceContext.CR_KEYCLOAK, "spec"
        return ReferenceContext.HELM_VALUES, "keycloak"

    return ReferenceContext.UNKNOWN, ""


def safe_parse_yaml(content: str) -> dict[str, Any] | list | None:
    """
    Safely parse YAML content, returning None on failure.

    Handles:
    - Multi-document YAML (returns first doc)
    - Template expressions (tries to parse anyway)
    - Invalid YAML (returns None)
    """
    try:
        # Try to parse as YAML
        docs = list(yaml.safe_load_all(content))
        if docs and isinstance(docs[0], dict) or docs and isinstance(docs[0], list):
            return docs[0]
        return None
    except yaml.YAMLError:
        return None


def get_surrounding_text(content: str, start: int, end: int, chars: int = 500) -> str:
    """Get text surrounding a match for context detection."""
    context_start = max(0, start - chars)
    context_end = min(len(content), end + chars)
    return content[context_start:context_end]


def should_skip_yaml_block(content: str, parsed: Any) -> tuple[bool, str]:
    """
    Determine if a YAML block should be skipped.

    Returns:
        (should_skip, reason)
    """
    # Skip if not a dict (e.g., just a list or scalar)
    if not isinstance(parsed, dict):
        return True, "not a dict"

    # Skip empty dicts
    if not parsed:
        return True, "empty"

    # Skip if it's heavily templated (lots of {{ }})
    template_count = content.count("{{")
    if template_count > 3:
        return True, f"heavily templated ({template_count} expressions)"

    # Skip if it's a Go template definition
    if "{{- define" in content or "{{- template" in content:
        return True, "Go template definition"

    # Skip shell variable assignments that look like YAML
    if re.match(r"^\s*\w+=", content.strip()):
        return True, "shell variable assignment"

    return False, ""


def extract_references_from_file(file_path: Path) -> ExtractionResult:
    """
    Extract all validatable references from a markdown file.

    Returns:
        ExtractionResult with references, skipped blocks, and errors
    """
    content = file_path.read_text(encoding="utf-8")
    references: list[ExtractedReference] = []
    skipped: list[tuple[int, str, str]] = []
    errors: list[tuple[int, str]] = []

    # Extract --set flags from Helm commands
    try:
        helm_refs = extract_helm_set_flags(content, file_path)
        references.extend(helm_refs)
    except Exception as e:
        errors.append((0, f"Error extracting helm --set flags: {e}"))

    # Extract YAML blocks
    yaml_blocks = extract_yaml_blocks(content)

    for line_no, yaml_content, _lang_hint in yaml_blocks:
        # Try to parse YAML
        parsed = safe_parse_yaml(yaml_content)

        if parsed is None:
            # Check if it's intentionally invalid or just a snippet
            if "..." in yaml_content or yaml_content.strip().startswith("#"):
                skipped.append(
                    (line_no, "incomplete/comment-only YAML", yaml_content[:100])
                )
            else:
                errors.append((line_no, "Failed to parse YAML"))
            continue

        # Check if we should skip this block
        should_skip, skip_reason = should_skip_yaml_block(yaml_content, parsed)
        if should_skip:
            skipped.append((line_no, skip_reason, yaml_content[:100]))
            continue

        # Get surrounding text for context detection
        # Find the position in the original content
        block_pos = content.find(yaml_content)
        surrounding = get_surrounding_text(
            content, block_pos, block_pos + len(yaml_content)
        )

        # Detect context
        context, parent_path = detect_yaml_context(parsed, yaml_content, surrounding)

        references.append(
            ExtractedReference(
                file=file_path,
                line=line_no,
                context=context,
                content=parsed,
                raw=yaml_content,
                surrounding_text=surrounding[:300],
                parent_path=parent_path,
            )
        )

    return ExtractionResult(
        file=file_path,
        references=references,
        skipped=skipped,
        errors=errors,
    )


def extract_all_references(
    docs_path: Path,
    examples_path: Path | None = None,
    include_patterns: list[str] | None = None,
) -> list[ExtractionResult]:
    """
    Extract references from all documentation files.

    Args:
        docs_path: Path to docs directory
        examples_path: Optional path to examples directory
        include_patterns: Optional glob patterns to include (default: *.md)

    Returns:
        List of ExtractionResult for each file processed
    """
    results = []
    patterns = include_patterns or ["**/*.md"]

    # Process docs directory
    for pattern in patterns:
        # Use glob for patterns with **, rglob for simple patterns
        if "**" in pattern:
            file_iter = docs_path.glob(pattern)
        else:
            file_iter = docs_path.rglob(pattern)

        for file_path in file_iter:
            if file_path.is_file():
                result = extract_references_from_file(file_path)
                results.append(result)

    # Process examples directory
    if examples_path and examples_path.exists():
        for yaml_file in examples_path.glob("*.yaml"):
            result = extract_references_from_yaml_file(yaml_file)
            results.append(result)

    return results


def extract_references_from_yaml_file(file_path: Path) -> ExtractionResult:
    """Extract references from a standalone YAML file (e.g., examples/)."""
    content = file_path.read_text(encoding="utf-8")
    references: list[ExtractedReference] = []
    skipped: list[tuple[int, str, str]] = []
    errors: list[tuple[int, str]] = []

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError as e:
        errors.append((1, f"Failed to parse YAML: {e}"))
        return ExtractionResult(
            file=file_path, references=references, skipped=skipped, errors=errors
        )

    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            skipped.append((1, f"document {i} is not a dict", str(doc)[:100]))
            continue

        # Detect context for the document
        context, parent_path = detect_yaml_context(doc, content, "")

        references.append(
            ExtractedReference(
                file=file_path,
                line=1,  # YAML files don't have easy line tracking for multi-doc
                context=context,
                content=doc,
                raw=content,
                parent_path=parent_path,
                metadata={"document_index": i},
            )
        )

    return ExtractionResult(
        file=file_path,
        references=references,
        skipped=skipped,
        errors=errors,
    )


def print_extraction_report(
    results: list[ExtractionResult], verbose: bool = False
) -> None:
    """Print a summary report of extraction results."""
    total_refs = 0
    total_skipped = 0
    total_errors = 0

    context_counts: dict[ReferenceContext, int] = dict.fromkeys(ReferenceContext, 0)

    print("\n" + "=" * 70)
    print("EXTRACTION REPORT")
    print("=" * 70)

    for result in results:
        if result.references or result.errors or (verbose and result.skipped):
            print(f"\n📄 {result.file}")

            for ref in result.references:
                context_counts[ref.context] += 1
                total_refs += 1

                # Show brief info about each reference
                if ref.context == ReferenceContext.HELM_SET:
                    print(f"  L{ref.line:4d} [HELM-SET] {ref.content}")
                else:
                    content_preview = str(ref.content)[:60].replace("\n", " ")
                    print(
                        f"  L{ref.line:4d} [{ref.context.value:12s}] {content_preview}..."
                    )

            for line, reason, _content in result.skipped:
                total_skipped += 1
                if verbose:
                    print(f"  L{line:4d} [SKIPPED] {reason}")

            for line, error in result.errors:
                total_errors += 1
                print(f"  L{line:4d} ❌ ERROR: {error}")

    print("\n" + "-" * 70)
    print("SUMMARY")
    print("-" * 70)
    print(f"Total references extracted: {total_refs}")
    print(f"Total blocks skipped:       {total_skipped}")
    print(f"Total errors:               {total_errors}")
    print("\nBy context:")
    for ctx, count in sorted(context_counts.items(), key=lambda x: -x[1]):
        if count > 0:
            print(f"  {ctx.value:15s}: {count}")


def export_to_json(results: list[ExtractionResult]) -> dict[str, Any]:
    """Export extraction results to JSON-serializable format."""
    # Use separate typed variables to avoid type inference issues
    summary: dict[str, Any] = {
        "total_references": 0,
        "total_skipped": 0,
        "total_errors": 0,
        "by_context": {},
    }

    validatable: dict[str, list[dict[str, Any]]] = {
        "helm_set": [],
        "helm_values": [],
        "cr_keycloak": [],
        "cr_realm": [],
        "cr_client": [],
    }

    skipped_list: list[dict[str, Any]] = []
    errors_list: list[dict[str, Any]] = []
    context_counts: dict[str, int] = {}

    for result in results:
        file_str = str(result.file)

        for ref in result.references:
            ctx_name = ref.context.value
            context_counts[ctx_name] = context_counts.get(ctx_name, 0) + 1
            summary["total_references"] += 1

            ref_data: dict[str, Any] = {
                "file": file_str,
                "line": ref.line,
                "context": ctx_name,
                "parent_path": ref.parent_path,
            }

            if ref.context == ReferenceContext.HELM_SET:
                ref_data["key"] = ref.content
                ref_data["value"] = ref.metadata.get("value", "")
                ref_data["chart_name"] = ref.metadata.get("chart_name", "unknown")
                validatable["helm_set"].append(ref_data)
            elif ref.context == ReferenceContext.HELM_VALUES:
                ref_data["content"] = ref.content
                validatable["helm_values"].append(ref_data)
            elif ref.context == ReferenceContext.CR_KEYCLOAK:
                ref_data["content"] = ref.content
                validatable["cr_keycloak"].append(ref_data)
            elif ref.context == ReferenceContext.CR_REALM:
                ref_data["content"] = ref.content
                validatable["cr_realm"].append(ref_data)
            elif ref.context == ReferenceContext.CR_CLIENT:
                ref_data["content"] = ref.content
                validatable["cr_client"].append(ref_data)

        for line, reason, _content in result.skipped:
            summary["total_skipped"] += 1
            skipped_list.append(
                {
                    "file": file_str,
                    "line": line,
                    "reason": reason,
                }
            )

        for line, error in result.errors:
            summary["total_errors"] += 1
            errors_list.append(
                {
                    "file": file_str,
                    "line": line,
                    "error": error,
                }
            )

    summary["by_context"] = context_counts

    return {
        "summary": summary,
        "validatable": validatable,
        "skipped": skipped_list,
        "errors": errors_list,
    }


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Extract validatable schema references from documentation"
    )
    parser.add_argument(
        "--docs",
        "-d",
        type=Path,
        help="Path to docs directory (default: docs/)",
    )
    parser.add_argument(
        "--examples",
        "-e",
        type=Path,
        help="Path to examples directory (default: examples/)",
    )
    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output as JSON instead of human-readable report",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show verbose output including skipped blocks",
    )

    args = parser.parse_args()

    # Default paths
    project_root = Path(__file__).parent.parent.parent
    docs_path = args.docs or (project_root / "docs")
    examples_path = args.examples or (project_root / "examples")

    if not docs_path.exists():
        print(f"Error: docs path does not exist: {docs_path}", file=sys.stderr)
        sys.exit(1)

    if not args.json:
        print(f"Extracting references from: {docs_path}")
        if examples_path.exists():
            print(f"Also scanning examples from: {examples_path}")

    results = extract_all_references(
        docs_path, examples_path if examples_path.exists() else None
    )

    if args.json:
        output = export_to_json(results)
        print(json.dumps(output, indent=2, default=str))
    else:
        print_extraction_report(results, verbose=args.verbose)
