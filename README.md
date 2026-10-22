# bloodhound-enrich

`bloodhound-enrich` adds explicitly tagged, inferred relationships to a
BloodHound Neo4j graph using declarative naming conventions.

It previews changes by default. Use `--apply` only after reviewing the output.

```bash
bloodhound-enrich
bloodhound-enrich --apply
bloodhound-enrich --list-conventions
bloodhound-enrich --convention ggp_tot_adm_server
```

Neo4j connection settings can be supplied with `--target`, `--user`, and
`--password`, or through `BLOODHOUND_NEO4J_URI`,
`BLOODHOUND_NEO4J_USER`, and `BLOODHOUND_NEO4J_PASSWORD`.

## Adding a convention

Add another `[[conventions]]` table to `default_conventions.toml`, or copy that
file and pass the copy with `--config`.

```toml
[[conventions]]
id = "example_rule"
description = "Explain the evidence behind this inference"
enabled = true
confidence = "medium"

source_label = "Group"
source_property = "samaccountname"
source_regex = '^PREFIX_(?P<asset>[A-Z0-9-]+)$'
regex_mode = "fullmatch"
case_sensitive = false

target_label = "Computer"
target_property = "name"
target_template = "{asset}.{domain}"

relationship = "AdminTo"
direction = "source_to_target"
edge_properties = { isacl = false }
expand_group_members = true
```

Named regex captures and source-node properties are available to
`target_template`. Rules may use `fullmatch`, `match`, or `search`, and may
reverse the edge with `direction = "target_to_source"`.

For conventions whose source is a `Group`, `expand_group_members = true` keeps
the inferred group edge and also creates the same relationship directly from
each user with a direct `MemberOf` edge to that group. This makes paths such as
`(:User)-[:AdminTo]->(:Computer)` available without changing the underlying
group membership data.

Created edges include these properties:

- `inferred = true`
- `inference_source = "bloodhound-enrich"`
- `inference_convention = <rule id>`
- `inference_confidence = <configured confidence>`
- `inference_version = <tool version>`
- `inferred_at` and `lastseen`

`AdminTo` is a BloodHound post-processed relationship. For those plans, the
tool also persists native `ADLocalGroup`, `LocalToComputer`, and
`MemberOfLocalGroup` evidence. BloodHound can therefore regenerate the
`AdminTo` edges during later analysis runs instead of discarding them. The raw
evidence is tagged with the same inference metadata; post-processed `AdminTo`
edges may contain BloodHound's own properties instead.

If an edge of the requested type already exists between the same nodes, the
tool leaves it untouched rather than labelling collector evidence as inferred.

To inspect inferred edges:

```cypher
MATCH (source)-[edge]->(target)
WHERE edge.inference_source = 'bloodhound-enrich'
RETURN source, edge, target
```

To remove only relationships created by this tool, after reviewing them:

```cypher
MATCH ()-[edge]->()
WHERE edge.inference_source = 'bloodhound-enrich'
DELETE edge

WITH 1 AS ignored
MATCH (node:ADLocalGroup)
WHERE node.inference_source = 'bloodhound-enrich'
DETACH DELETE node
```

Run BloodHound analysis after cleanup so it reconciles derived `AdminTo`
relationships from the remaining evidence.
