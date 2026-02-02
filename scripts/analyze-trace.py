#!/usr/bin/env python3
"""Analyze OpenTelemetry trace files from integration tests.

This tool helps debug test failures by filtering and visualizing trace data
collected during test runs.

Usage:
    python scripts/analyze-trace.py .tmp/traces/traces.jsonl --summary
    python scripts/analyze-trace.py .tmp/traces/traces.jsonl --errors-only
    python scripts/analyze-trace.py .tmp/traces/traces.jsonl --filter "test_create_realm"
    python scripts/analyze-trace.py .tmp/traces/traces.jsonl --time-range "2024-01-01T10:00:00" "2024-01-01T10:05:00"
    python scripts/analyze-trace.py .tmp/traces/traces.jsonl --tree
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_timestamp(ts: str | int | None) -> datetime | None:
    """Parse timestamp from various formats."""
    if ts is None:
        return None

    if isinstance(ts, int):
        # Nanoseconds since epoch
        return datetime.fromtimestamp(ts / 1e9)

    if isinstance(ts, str):
        # ISO format
        try:
            # Handle various ISO formats
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S",
            ]:
                try:
                    return datetime.strptime(ts, fmt)
                except ValueError:
                    continue
        except Exception:
            # Silently ignore any parsing errors - this is a best-effort parsing function
            # that tries multiple formats. Returning None signals parsing failure.
            pass
    return None


def load_traces(path: Path) -> list[dict[str, Any]]:
    """Load traces from JSONL file(s)."""
    traces = []

    if path.is_dir():
        # Load all .jsonl files in directory
        for file in path.rglob("*.jsonl"):
            traces.extend(load_traces(file))
    else:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        traces.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        print(f"Warning: Could not parse line: {e}", file=sys.stderr)

    return traces


def extract_spans(traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract individual spans from trace data."""
    spans = []

    for trace in traces:
        # Handle different OTLP formats
        resource_spans = trace.get("resourceSpans", [])
        for rs in resource_spans:
            resource = rs.get("resource", {})
            resource_attrs = {
                attr.get("key"): attr.get("value", {}).get(
                    "stringValue", attr.get("value", {}).get("intValue")
                )
                for attr in resource.get("attributes", [])
            }

            scope_spans = rs.get("scopeSpans", [])
            for ss in scope_spans:
                scope = ss.get("scope", {})
                for span in ss.get("spans", []):
                    span_data = {
                        "trace_id": span.get("traceId"),
                        "span_id": span.get("spanId"),
                        "parent_span_id": span.get("parentSpanId"),
                        "name": span.get("name"),
                        "kind": span.get("kind"),
                        "start_time": parse_timestamp(span.get("startTimeUnixNano")),
                        "end_time": parse_timestamp(span.get("endTimeUnixNano")),
                        "status": span.get("status", {}),
                        "attributes": {
                            attr.get("key"): attr.get("value", {}).get(
                                "stringValue", attr.get("value", {}).get("intValue")
                            )
                            for attr in span.get("attributes", [])
                        },
                        "events": span.get("events", []),
                        "resource": resource_attrs,
                        "scope": scope.get("name"),
                    }
                    spans.append(span_data)

    return spans


def filter_spans(
    spans: list[dict[str, Any]],
    *,
    filter_text: str | None = None,
    errors_only: bool = False,
    time_start: datetime | None = None,
    time_end: datetime | None = None,
) -> list[dict[str, Any]]:
    """Filter spans based on criteria."""
    result = []

    for span in spans:
        # Filter by error status
        if errors_only:
            status = span.get("status", {})
            if status.get("code") != 2:  # STATUS_CODE_ERROR = 2
                continue

        # Filter by text (searches name and attributes)
        if filter_text:
            text_lower = filter_text.lower()
            name_match = text_lower in span.get("name", "").lower()
            attr_match = any(
                text_lower in str(v).lower()
                for v in span.get("attributes", {}).values()
            )
            if not (name_match or attr_match):
                continue

        # Filter by time range
        if time_start and span.get("start_time") and span["start_time"] < time_start:
            continue
        if time_end and span.get("end_time") and span["end_time"] > time_end:
            continue

        result.append(span)

    return result


def print_span(span: dict[str, Any], indent: int = 0) -> None:
    """Print a single span with formatting."""
    prefix = "  " * indent

    # Status indicator
    status = span.get("status", {})
    if status.get("code") == 2:
        status_icon = "❌"
    elif status.get("code") == 1:
        status_icon = "✅"
    else:
        status_icon = "⏺️"

    # Duration
    duration = ""
    if span.get("start_time") and span.get("end_time"):
        delta = span["end_time"] - span["start_time"]
        duration = f" ({delta.total_seconds() * 1000:.1f}ms)"

    print(f"{prefix}{status_icon} {span.get('name')}{duration}")

    # Print attributes if present
    attrs = span.get("attributes", {})
    if attrs:
        for key, value in attrs.items():
            if key not in ["otel.library.name", "otel.library.version"]:
                print(f"{prefix}   {key}: {value}")

    # Print error message if present
    if status.get("message"):
        print(f"{prefix}   error: {status['message']}")

    # Print events (like exceptions)
    for event in span.get("events", []):
        event_name = event.get("name", "event")
        print(f"{prefix}   📎 {event_name}")
        for attr in event.get("attributes", []):
            key = attr.get("key")
            value = attr.get("value", {}).get("stringValue", "")
            if key and value:
                # Truncate long stack traces
                if len(value) > 200:
                    value = value[:200] + "..."
                print(f"{prefix}      {key}: {value}")


def print_summary(spans: list[dict[str, Any]]) -> None:
    """Print a summary of the trace data."""
    if not spans:
        print("No spans found")
        return

    # Count by status
    status_counts: dict[str, int] = defaultdict(int)
    for span in spans:
        status = span.get("status", {})
        code = status.get("code", 0)
        if code == 2:
            status_counts["error"] += 1
        elif code == 1:
            status_counts["ok"] += 1
        else:
            status_counts["unset"] += 1

    # Count by operation name
    operation_counts: dict[str, int] = defaultdict(int)
    for span in spans:
        name = span.get("name", "unknown")
        operation_counts[name] += 1

    # Time range
    start_times = [s["start_time"] for s in spans if s.get("start_time")]
    end_times = [s["end_time"] for s in spans if s.get("end_time")]

    print("=" * 60)
    print("TRACE SUMMARY")
    print("=" * 60)
    print(f"Total spans: {len(spans)}")
    print(f"  ✅ OK: {status_counts['ok']}")
    print(f"  ❌ Error: {status_counts['error']}")
    print(f"  ⏺️ Unset: {status_counts['unset']}")

    if start_times and end_times:
        print("\nTime range:")
        print(f"  Start: {min(start_times)}")
        print(f"  End: {max(end_times)}")

    print("\nTop operations (by count):")
    for name, count in sorted(operation_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"  {count:4d}x {name}")

    # Show error details if any
    if status_counts["error"] > 0:
        print("\n❌ Error spans:")
        error_spans = [s for s in spans if s.get("status", {}).get("code") == 2]
        for span in error_spans[:10]:  # Limit to first 10
            print_span(span, indent=1)
        if len(error_spans) > 10:
            print(f"  ... and {len(error_spans) - 10} more errors")


def build_trace_tree(spans: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Build a tree structure from spans."""
    # Group by trace ID
    by_trace: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for span in spans:
        trace_id = span.get("trace_id")
        if trace_id:
            by_trace[trace_id].append(span)

    return by_trace


def print_tree(spans: list[dict[str, Any]]) -> None:
    """Print spans in tree format grouped by trace."""
    traces = build_trace_tree(spans)

    if not traces:
        print("No traces found")
        return

    print(f"Found {len(traces)} trace(s)")
    print("=" * 60)

    def print_children(
        by_parent: dict[str | None, list[dict[str, Any]]],
        parent_id: str | None,
        depth: int = 0,
    ) -> None:
        """Recursively print child spans."""
        children = by_parent.get(parent_id, [])
        # Sort by start time
        children.sort(key=lambda s: s.get("start_time") or datetime.min)
        for child in children:
            print_span(child, indent=depth)
            print_children(by_parent, child.get("span_id"), depth + 1)

    for trace_id, trace_spans in traces.items():
        print(f"\n🔗 Trace: {trace_id[:16]}...")

        # Build parent-child relationships
        by_parent: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
        for span in trace_spans:
            parent = span.get("parent_span_id")
            by_parent[parent].append(span)

        # Start with root spans (no parent)
        print_children(by_parent, None)
        print_children(by_parent, "")  # Some spans have empty string parent


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze OpenTelemetry trace files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("path", type=Path, help="Path to trace file or directory")
    parser.add_argument(
        "--filter",
        "-f",
        dest="filter_text",
        help="Filter spans by text (name or attributes)",
    )
    parser.add_argument(
        "--errors-only", "-e", action="store_true", help="Show only error spans"
    )
    parser.add_argument(
        "--time-range",
        "-t",
        nargs=2,
        metavar=("START", "END"),
        help="Filter by time range (ISO format)",
    )
    parser.add_argument(
        "--summary", "-s", action="store_true", help="Show summary statistics"
    )
    parser.add_argument(
        "--tree", action="store_true", help="Show spans in tree format by trace"
    )
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--limit",
        "-n",
        type=int,
        default=100,
        help="Limit number of spans shown (default: 100)",
    )

    args = parser.parse_args()

    # Load traces
    if not args.path.exists():
        print(f"Error: Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading traces from {args.path}...", file=sys.stderr)
    traces = load_traces(args.path)
    print(f"Loaded {len(traces)} trace record(s)", file=sys.stderr)

    # Extract spans
    spans = extract_spans(traces)
    print(f"Extracted {len(spans)} span(s)", file=sys.stderr)

    # Parse time range if provided
    time_start = None
    time_end = None
    if args.time_range:
        time_start = parse_timestamp(args.time_range[0])
        time_end = parse_timestamp(args.time_range[1])

    # Filter spans
    filtered = filter_spans(
        spans,
        filter_text=args.filter_text,
        errors_only=args.errors_only,
        time_start=time_start,
        time_end=time_end,
    )
    print(f"After filtering: {len(filtered)} span(s)", file=sys.stderr)
    print("", file=sys.stderr)

    # Output
    if args.json:
        # JSON output (convert datetime to string)
        for span in filtered[: args.limit]:
            span_copy = span.copy()
            if span_copy.get("start_time"):
                span_copy["start_time"] = span_copy["start_time"].isoformat()
            if span_copy.get("end_time"):
                span_copy["end_time"] = span_copy["end_time"].isoformat()
            print(json.dumps(span_copy))
    elif args.summary:
        print_summary(filtered)
    elif args.tree:
        print_tree(filtered[: args.limit])
    else:
        # Default: list spans
        for span in filtered[: args.limit]:
            print_span(span)
            print()

        if len(filtered) > args.limit:
            print(
                f"... showing {args.limit} of {len(filtered)} spans (use --limit to show more)"
            )


if __name__ == "__main__":
    main()
