from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from neo4j import GraphDatabase
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable

from . import __version__


TOOL_NAME = "bloodhound-enrich"
CONFIG_VERSION = 1
IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
VALID_DIRECTIONS = {"source_to_target", "target_to_source"}
VALID_REGEX_MODES = {"fullmatch", "match", "search"}
ALLOWED_CONVENTION_KEYS = {
    "id",
    "description",
    "enabled",
    "confidence",
    "source_label",
    "source_property",
    "source_regex",
    "regex_mode",
    "case_sensitive",
    "target_label",
    "target_property",
    "target_template",
    "relationship",
    "direction",
    "edge_properties",
    "expand_group_members",
}


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Convention:
    id: str
    description: str
    source_label: str
    source_property: str
    source_regex: str
    target_label: str
    target_property: str
    target_template: str
    relationship: str
    direction: str = "source_to_target"
    regex_mode: str = "fullmatch"
    case_sensitive: bool = False
    enabled: bool = True
    confidence: str = "medium"
    edge_properties: Mapping[str, Any] = field(default_factory=dict)
    expand_group_members: bool = False

    def compiled_regex(self) -> re.Pattern[str]:
        flags = 0 if self.case_sensitive else re.IGNORECASE
        try:
            return re.compile(self.source_regex, flags)
        except re.error as exc:
            raise ConfigurationError(
                f"Convention '{self.id}' has an invalid source_regex: {exc}"
            ) from exc


@dataclass(frozen=True)
class NodeRecord:
    object_id: str
    name: str
    label: str
    properties: Mapping[str, Any]


@dataclass
class EdgePlan:
    convention: Convention
    from_node: NodeRecord
    to_node: NodeRecord
    rendered_target: str
    exists: bool = False

    @property
    def key(self) -> str:
        return "\x1f".join(
            (
                self.convention.id,
                self.from_node.object_id,
                self.convention.relationship,
                self.to_node.object_id,
            )
        )


@dataclass
class ConventionReport:
    convention: Convention
    scanned: int = 0
    pattern_matches: int = 0
    plans: list[EdgePlan] = field(default_factory=list)
    unresolved: list[tuple[str, str]] = field(default_factory=list)
    ambiguous: list[tuple[str, str, list[str]]] = field(default_factory=list)
    invalid_sources: list[str] = field(default_factory=list)


def _validate_identifier(value: str, field_name: str, convention_id: str) -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise ConfigurationError(
            f"Convention '{convention_id}' has invalid {field_name} '{value}'. "
            "Use letters, numbers, and underscores, beginning with a letter."
        )
    return value


def _require_string(raw: Mapping[str, Any], key: str, convention_id: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(
            f"Convention '{convention_id}' requires a non-empty '{key}' string."
        )
    return value.strip()


def parse_config(data: Mapping[str, Any]) -> list[Convention]:
    version = data.get("version")
    if version != CONFIG_VERSION:
        raise ConfigurationError(
            f"Unsupported configuration version {version!r}; expected {CONFIG_VERSION}."
        )

    raw_conventions = data.get("conventions")
    if not isinstance(raw_conventions, list) or not raw_conventions:
        raise ConfigurationError("Configuration must contain at least one [[conventions]] rule.")

    conventions: list[Convention] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_conventions, start=1):
        if not isinstance(raw, dict):
            raise ConfigurationError(f"Convention #{index} must be a TOML table.")

        convention_id = str(raw.get("id", f"#{index}"))
        unknown = set(raw) - ALLOWED_CONVENTION_KEYS
        if unknown:
            raise ConfigurationError(
                f"Convention '{convention_id}' has unknown field(s): "
                + ", ".join(sorted(unknown))
            )
        convention_id = _require_string(raw, "id", convention_id)
        _validate_identifier(convention_id, "id", convention_id)
        if convention_id in seen_ids:
            raise ConfigurationError(f"Duplicate convention id '{convention_id}'.")
        seen_ids.add(convention_id)

        source_label = _validate_identifier(
            _require_string(raw, "source_label", convention_id),
            "source_label",
            convention_id,
        )
        source_property = _validate_identifier(
            _require_string(raw, "source_property", convention_id),
            "source_property",
            convention_id,
        )
        target_label = _validate_identifier(
            _require_string(raw, "target_label", convention_id),
            "target_label",
            convention_id,
        )
        target_property = _validate_identifier(
            _require_string(raw, "target_property", convention_id),
            "target_property",
            convention_id,
        )
        relationship = _validate_identifier(
            _require_string(raw, "relationship", convention_id),
            "relationship",
            convention_id,
        )

        direction = str(raw.get("direction", "source_to_target"))
        if direction not in VALID_DIRECTIONS:
            raise ConfigurationError(
                f"Convention '{convention_id}' has invalid direction '{direction}'."
            )
        regex_mode = str(raw.get("regex_mode", "fullmatch"))
        if regex_mode not in VALID_REGEX_MODES:
            raise ConfigurationError(
                f"Convention '{convention_id}' has invalid regex_mode '{regex_mode}'."
            )
        edge_properties = raw.get("edge_properties", {})
        if not isinstance(edge_properties, dict):
            raise ConfigurationError(
                f"Convention '{convention_id}' edge_properties must be a TOML table."
            )
        expand_group_members = raw.get("expand_group_members", False)
        if not isinstance(expand_group_members, bool):
            raise ConfigurationError(
                f"Convention '{convention_id}' expand_group_members must be a boolean."
            )

        convention = Convention(
            id=convention_id,
            description=str(raw.get("description", "")).strip(),
            source_label=source_label,
            source_property=source_property,
            source_regex=_require_string(raw, "source_regex", convention_id),
            target_label=target_label,
            target_property=target_property,
            target_template=_require_string(raw, "target_template", convention_id),
            relationship=relationship,
            direction=direction,
            regex_mode=regex_mode,
            case_sensitive=bool(raw.get("case_sensitive", False)),
            enabled=bool(raw.get("enabled", True)),
            confidence=str(raw.get("confidence", "medium")).strip() or "medium",
            edge_properties=edge_properties,
            expand_group_members=expand_group_members,
        )
        if convention.expand_group_members and convention.source_label != "Group":
            raise ConfigurationError(
                f"Convention '{convention_id}' can only expand_group_members when "
                "source_label is 'Group'."
            )
        convention.compiled_regex()
        conventions.append(convention)

    return conventions


def load_config(path: Path | None) -> tuple[list[Convention], str]:
    if path is None:
        resource = resources.files("bloodhound_enrich").joinpath(
            "default_conventions.toml"
        )
        with resource.open("rb") as handle:
            data = tomllib.load(handle)
        source = str(resource)
    else:
        try:
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        except FileNotFoundError as exc:
            raise ConfigurationError(f"Configuration file not found: {path}") from exc
        except tomllib.TOMLDecodeError as exc:
            raise ConfigurationError(f"Invalid TOML in {path}: {exc}") from exc
        source = str(path)
    return parse_config(data), source


def _normalize(value: Any, case_sensitive: bool) -> str:
    text = str(value)
    return text if case_sensitive else text.casefold()


def _match_source(
    convention: Convention, pattern: re.Pattern[str], value: str
) -> re.Match[str] | None:
    matcher = getattr(pattern, convention.regex_mode)
    return matcher(value)


def _format_context(source: NodeRecord, match: re.Match[str]) -> dict[str, Any]:
    context: dict[str, Any] = {}
    for key, value in source.properties.items():
        context[str(key)] = value
        context.setdefault(str(key).lower(), value)
    context.update(
        {
            "source_name": source.name,
            "source_objectid": source.object_id,
        }
    )
    context.update({key: value for key, value in match.groupdict().items()})
    for index, value in enumerate(match.groups(), start=1):
        context[f"group{index}"] = value
    return context


def plan_convention(
    convention: Convention,
    sources: Sequence[NodeRecord],
    targets: Sequence[NodeRecord],
) -> ConventionReport:
    report = ConventionReport(convention=convention, scanned=len(sources))
    pattern = convention.compiled_regex()
    target_index: dict[str, list[NodeRecord]] = {}
    for target in targets:
        target_value = target.properties.get(convention.target_property)
        if target_value is None:
            continue
        key = _normalize(target_value, convention.case_sensitive)
        target_index.setdefault(key, []).append(target)

    for source in sources:
        source_value = source.properties.get(convention.source_property)
        if source_value is None:
            continue
        match = _match_source(convention, pattern, str(source_value))
        if match is None:
            continue
        report.pattern_matches += 1

        try:
            rendered = convention.target_template.format_map(
                _format_context(source, match)
            )
        except (KeyError, ValueError) as exc:
            report.invalid_sources.append(f"{source.name}: {exc}")
            continue

        candidates = target_index.get(
            _normalize(rendered, convention.case_sensitive), []
        )
        if not candidates:
            report.unresolved.append((source.name, rendered))
            continue
        if len(candidates) > 1:
            report.ambiguous.append(
                (source.name, rendered, [candidate.name for candidate in candidates])
            )
            continue

        target = candidates[0]
        if convention.direction == "source_to_target":
            from_node, to_node = source, target
        else:
            from_node, to_node = target, source
        report.plans.append(
            EdgePlan(
                convention=convention,
                from_node=from_node,
                to_node=to_node,
                rendered_target=rendered,
            )
        )

    return report


def _fetch_nodes(tx: Any, label: str, required_property: str) -> list[NodeRecord]:
    query = (
        f"MATCH (n:{label}) "
        f"WHERE n.{required_property} IS NOT NULL AND n.objectid IS NOT NULL "
        "RETURN n.objectid AS object_id, "
        "coalesce(n.name, n.objectid) AS name, properties(n) AS properties"
    )
    result = tx.run(query)
    rows = list(result)
    result.consume()
    return [
        NodeRecord(
            object_id=str(row["object_id"]),
            name=str(row["name"]),
            label=label,
            properties=dict(row["properties"]),
        )
        for row in rows
    ]


def _fetch_direct_user_members(
    tx: Any, group_ids: Sequence[str]
) -> dict[str, list[NodeRecord]]:
    query = (
        "UNWIND $group_ids AS group_id "
        "MATCH (member:User)-[:MemberOf]->(group:Group {objectid: group_id}) "
        "WHERE member.objectid IS NOT NULL "
        "RETURN group_id, member.objectid AS object_id, "
        "coalesce(member.name, member.objectid) AS name, "
        "properties(member) AS properties"
    )
    result = tx.run(query, group_ids=list(group_ids))
    rows = list(result)
    result.consume()
    members: dict[str, list[NodeRecord]] = {}
    for row in rows:
        members.setdefault(str(row["group_id"]), []).append(
            NodeRecord(
                object_id=str(row["object_id"]),
                name=str(row["name"]),
                label="User",
                properties=dict(row["properties"]),
            )
        )
    return members


def _expand_group_member_plans(
    report: ConventionReport,
    members_by_group: Mapping[str, Sequence[NodeRecord]],
) -> None:
    expanded: list[EdgePlan] = []
    seen = {plan.key for plan in report.plans}
    for plan in report.plans:
        source = (
            plan.from_node
            if report.convention.direction == "source_to_target"
            else plan.to_node
        )
        for member in members_by_group.get(source.object_id, ()):
            if report.convention.direction == "source_to_target":
                from_node, to_node = member, plan.to_node
            else:
                from_node, to_node = plan.from_node, member
            member_plan = EdgePlan(
                convention=report.convention,
                from_node=from_node,
                to_node=to_node,
                rendered_target=plan.rendered_target,
            )
            if member_plan.key not in seen:
                seen.add(member_plan.key)
                expanded.append(member_plan)
    report.plans.extend(expanded)


def discover(session: Any, convention: Convention) -> ConventionReport:
    sources = session.execute_read(
        _fetch_nodes, convention.source_label, convention.source_property
    )
    targets = session.execute_read(
        _fetch_nodes, convention.target_label, convention.target_property
    )
    report = plan_convention(convention, sources, targets)
    if convention.expand_group_members and report.plans:
        group_ids = sorted(
            {
                (
                    plan.from_node
                    if convention.direction == "source_to_target"
                    else plan.to_node
                ).object_id
                for plan in report.plans
            }
        )
        members_by_group = session.execute_read(
            _fetch_direct_user_members, group_ids
        )
        _expand_group_member_plans(report, members_by_group)
    return report


def _chunks(values: Sequence[Any], size: int = 500) -> Iterable[Sequence[Any]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def _group_plans(
    plans: Sequence[EdgePlan],
) -> dict[tuple[str, str, str], list[EdgePlan]]:
    groups: dict[tuple[str, str, str], list[EdgePlan]] = {}
    for plan in plans:
        key = (
            plan.convention.relationship,
            plan.from_node.label,
            plan.to_node.label,
        )
        groups.setdefault(key, []).append(plan)
    return groups


def _find_existing_batch(
    tx: Any,
    relationship: str,
    from_label: str,
    to_label: str,
    plans: Sequence[EdgePlan],
) -> set[str]:
    query = (
        "UNWIND $pairs AS pair "
        f"MATCH (source:{from_label} {{objectid: pair.from_id}}) "
        f"MATCH (target:{to_label} {{objectid: pair.to_id}}) "
        f"OPTIONAL MATCH (source)-[edge:{relationship}]->(target) "
        "RETURN pair.key AS key, count(edge) > 0 AS exists"
    )
    pairs = [
        {
            "key": plan.key,
            "from_id": plan.from_node.object_id,
            "to_id": plan.to_node.object_id,
        }
        for plan in plans
    ]
    result = tx.run(query, pairs=pairs)
    rows = list(result)
    result.consume()
    return {str(row["key"]) for row in rows if row["exists"]}


def mark_existing(session: Any, plans: Sequence[EdgePlan]) -> None:
    existing_keys: set[str] = set()
    for (relationship, from_label, to_label), grouped in _group_plans(plans).items():
        for batch in _chunks(grouped):
            existing_keys.update(
                session.execute_read(
                    _find_existing_batch,
                    relationship,
                    from_label,
                    to_label,
                    batch,
                )
            )
    for plan in plans:
        plan.exists = plan.key in existing_keys


def _create_batch(
    tx: Any,
    relationship: str,
    from_label: str,
    to_label: str,
    plans: Sequence[EdgePlan],
) -> tuple[int, int]:
    query = (
        "UNWIND $edges AS item "
        f"MATCH (source:{from_label} {{objectid: item.from_id}}) "
        f"MATCH (target:{to_label} {{objectid: item.to_id}}) "
        f"MERGE (source)-[edge:{relationship}]->(target) "
        "ON CREATE SET edge += item.properties, "
        "edge.inferred_at = datetime(), edge.lastseen = datetime() "
        "RETURN count(*) AS matched"
    )
    edges = []
    for plan in plans:
        properties = dict(plan.convention.edge_properties)
        properties.update(
            {
                "inferred": True,
                "inference_source": TOOL_NAME,
                "inference_convention": plan.convention.id,
                "inference_confidence": plan.convention.confidence,
                "inference_version": __version__,
            }
        )
        edges.append(
            {
                "from_id": plan.from_node.object_id,
                "to_id": plan.to_node.object_id,
                "properties": properties,
            }
        )

    result = tx.run(query, edges=edges)
    record = result.single()
    summary = result.consume()
    matched = int(record["matched"]) if record else 0
    return summary.counters.relationships_created, matched


def _is_admin_to_computer(plan: EdgePlan) -> bool:
    return (
        plan.convention.relationship == "AdminTo"
        and plan.from_node.label in {"Computer", "Group", "User"}
        and plan.to_node.label == "Computer"
    )


def _admin_evidence_properties(plan: EdgePlan) -> dict[str, Any]:
    properties = dict(plan.convention.edge_properties)
    properties.update(
        {
            "inferred": True,
            "inference_source": TOOL_NAME,
            "inference_convention": plan.convention.id,
            "inference_confidence": plan.convention.confidence,
            "inference_version": __version__,
        }
    )
    return properties


def _create_admin_evidence_batch(
    tx: Any,
    from_label: str,
    plans: Sequence[EdgePlan],
) -> int:
    """Persist AdminTo evidence in BloodHound's analysis-owned local-group model."""
    query = (
        "UNWIND $edges AS item "
        f"MATCH (source:{from_label} {{objectid: item.from_id}}) "
        "MATCH (target:Computer {objectid: item.to_id}) "
        "MERGE (local_group:Base:ADLocalGroup {objectid: item.local_group_id}) "
        "ON CREATE SET local_group += item.local_group_properties, "
        "local_group.inferred_at = datetime() "
        "MERGE (local_group)-[host_edge:LocalToComputer]->(target) "
        "ON CREATE SET host_edge += item.edge_properties, "
        "host_edge.inferred_at = datetime() "
        "MERGE (source)-[member_edge:MemberOfLocalGroup]->(local_group) "
        "ON CREATE SET member_edge += item.edge_properties, "
        "member_edge.inferred_at = datetime() "
        "RETURN count(*) AS matched"
    )
    edges = []
    for plan in plans:
        local_group_id = f"{TOOL_NAME}:{plan.to_node.object_id}-544"
        edge_properties = _admin_evidence_properties(plan)
        local_group_properties = dict(edge_properties)
        local_group_properties.update(
            {
                "name": f"ADMINISTRATORS@{plan.to_node.name}",
                "domain": plan.to_node.properties.get("domain", ""),
            }
        )
        edges.append(
            {
                "from_id": plan.from_node.object_id,
                "to_id": plan.to_node.object_id,
                "local_group_id": local_group_id,
                "local_group_properties": local_group_properties,
                "edge_properties": edge_properties,
            }
        )

    result = tx.run(query, edges=edges)
    record = result.single()
    result.consume()
    return int(record["matched"]) if record else 0


def apply_admin_evidence(session: Any, plans: Sequence[EdgePlan]) -> int:
    evidence_plans = [plan for plan in plans if _is_admin_to_computer(plan)]
    grouped: dict[str, list[EdgePlan]] = {}
    for plan in evidence_plans:
        grouped.setdefault(plan.from_node.label, []).append(plan)

    matched = 0
    for from_label, label_plans in grouped.items():
        for batch in _chunks(label_plans):
            matched += session.execute_write(
                _create_admin_evidence_batch,
                from_label,
                batch,
            )
    return matched


def apply_plans(session: Any, plans: Sequence[EdgePlan]) -> tuple[int, int]:
    # AdminTo is owned by BloodHound post-processing. Persist its source evidence
    # even when the derived edge already exists so future analysis keeps it.
    apply_admin_evidence(session, plans)

    pending = [plan for plan in plans if not plan.exists]
    created = 0
    matched = 0
    for (relationship, from_label, to_label), grouped in _group_plans(pending).items():
        for batch in _chunks(grouped):
            batch_created, batch_matched = session.execute_write(
                _create_batch,
                relationship,
                from_label,
                to_label,
                batch,
            )
            created += batch_created
            matched += batch_matched
    return created, matched


def print_report(report: ConventionReport, verbose: bool = False) -> None:
    existing = sum(plan.exists for plan in report.plans)
    pending = len(report.plans) - existing
    print(f"[{report.convention.id}] {report.convention.description}")
    print(
        f"  scanned={report.scanned} pattern_matches={report.pattern_matches} "
        f"resolved={len(report.plans)} existing={existing} would_create={pending} "
        f"unresolved={len(report.unresolved)} ambiguous={len(report.ambiguous)} "
        f"invalid={len(report.invalid_sources)}"
    )

    detail_limit = None if verbose else 10
    for source, rendered in report.unresolved[:detail_limit]:
        print(f"  unresolved: {source} -> {rendered}")
    for source, rendered, candidates in report.ambiguous[:detail_limit]:
        print(
            f"  ambiguous: {source} -> {rendered} "
            f"({', '.join(candidates)})"
        )
    for message in report.invalid_sources[:detail_limit]:
        print(f"  invalid: {message}")
    if not verbose:
        hidden = (
            max(0, len(report.unresolved) - 10)
            + max(0, len(report.ambiguous) - 10)
            + max(0, len(report.invalid_sources) - 10)
        )
        if hidden:
            print(f"  ... {hidden} additional issue(s); use --verbose to display all")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Infer BloodHound relationships from declarative naming conventions. "
            "Runs in preview mode unless --apply is supplied."
        )
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="TOML convention file (default: packaged conventions)",
    )
    parser.add_argument(
        "--convention",
        action="append",
        dest="conventions",
        metavar="ID",
        help="Run only this convention; may be repeated",
    )
    parser.add_argument(
        "--list-conventions",
        action="store_true",
        help="List loaded conventions and exit",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create the inferred relationships (default is preview only)",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "-t",
        "--target",
        default=os.environ.get("BLOODHOUND_NEO4J_URI", "bolt://localhost:7687"),
        help="Neo4j URI",
    )
    parser.add_argument(
        "-u",
        "--user",
        default=os.environ.get("BLOODHOUND_NEO4J_USER", "neo4j"),
        help="Neo4j username",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=os.environ.get(
            "BLOODHOUND_NEO4J_PASSWORD", "bloodhoundcommunityedition"
        ),
        help="Neo4j password (or set BLOODHOUND_NEO4J_PASSWORD)",
    )
    return parser


def _select_conventions(
    conventions: Sequence[Convention], selected_ids: Sequence[str] | None
) -> list[Convention]:
    enabled = [convention for convention in conventions if convention.enabled]
    if not selected_ids:
        return enabled
    requested = set(selected_ids)
    known = {convention.id for convention in conventions}
    unknown = requested - known
    if unknown:
        raise ConfigurationError(
            "Unknown convention id(s): " + ", ".join(sorted(unknown))
        )
    return [convention for convention in conventions if convention.id in requested]


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        conventions, config_source = load_config(args.config)
        selected = _select_conventions(conventions, args.conventions)
    except ConfigurationError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2

    if args.list_conventions:
        print(f"Configuration: {config_source}")
        for convention in conventions:
            state = "enabled" if convention.enabled else "disabled"
            print(
                f"{convention.id}\t{state}\t"
                f"{convention.source_label}-[{convention.relationship}]->"
                f"{convention.target_label}\t{convention.description}"
            )
        return 0
    if not selected:
        print("[-] No enabled conventions selected.", file=sys.stderr)
        return 2

    driver = None
    try:
        driver = GraphDatabase.driver(args.target, auth=(args.user, args.password))
        driver.verify_connectivity()
        reports: list[ConventionReport] = []
        with driver.session() as session:
            for convention in selected:
                report = discover(session, convention)
                mark_existing(session, report.plans)
                reports.append(report)
                print_report(report, verbose=args.verbose)

            plans = [plan for report in reports for plan in report.plans]
            pending = [plan for plan in plans if not plan.exists]
            if not args.apply:
                print(
                    f"[*] Preview complete: {len(pending)} relationship(s) would be "
                    "created. Re-run with --apply to write them."
                )
                return 0

            created, matched = apply_plans(session, plans)
            print(
                f"[+] Apply complete: created={created} matched={matched} "
                f"previously_existing={len(plans) - len(pending)}"
            )
            if matched != len(pending):
                print(
                    f"[!] {len(pending) - matched} planned relationship(s) were not "
                    "matched during apply; their endpoint nodes may have changed."
                )
                return 1
            return 0
    except AuthError:
        print(f"[-] Neo4j authentication failed for user '{args.user}'.", file=sys.stderr)
        return 1
    except ServiceUnavailable:
        print(f"[-] Could not connect to Neo4j at '{args.target}'.", file=sys.stderr)
        return 1
    except Neo4jError as exc:
        print(f"[-] Neo4j error: {exc}", file=sys.stderr)
        return 1
    finally:
        if driver is not None:
            driver.close()


if __name__ == "__main__":
    raise SystemExit(main())
