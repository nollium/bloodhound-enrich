import unittest

from bloodhound_enrich.cli import (
    ConfigurationError,
    Convention,
    ConventionReport,
    EdgePlan,
    NodeRecord,
    _create_admin_evidence_batch,
    _expand_group_member_plans,
    _fetch_direct_user_members,
    _fetch_nodes,
    discover,
    parse_config,
    plan_convention,
)


def node(object_id, name, label, **properties):
    values = {"objectid": object_id, "name": name, **properties}
    return NodeRecord(object_id, name, label, values)


class ConventionPlanningTests(unittest.TestCase):
    def setUp(self):
        self.convention = Convention(
            id="ggp_tot_adm_server",
            description="test",
            source_label="Group",
            source_property="samaccountname",
            source_regex=r"^_GGP_TOT_ADM_(?P<hostname>[A-Z0-9-]+)$",
            target_label="Computer",
            target_property="name",
            target_template="{hostname}.{domain}",
            relationship="AdminTo",
        )

    def test_convention_resolves_group_to_computer_case_insensitively(self):
        group = node(
            "group-sid",
            "_GGP_TOT_ADM_HOST@EXAMPLE.LOCAL",
            "Group",
            samaccountname="_ggp_tot_adm_host",
            domain="EXAMPLE.LOCAL",
        )
        computer = node(
            "computer-sid",
            "HOST.EXAMPLE.LOCAL",
            "Computer",
        )

        report = plan_convention(self.convention, [group], [computer])

        self.assertEqual(report.pattern_matches, 1)
        self.assertEqual(len(report.plans), 1)
        self.assertEqual(report.plans[0].from_node, group)
        self.assertEqual(report.plans[0].to_node, computer)
        self.assertEqual(report.unresolved, [])

    def test_missing_target_is_reported_without_a_plan(self):
        group = node(
            "group-sid",
            "_GGP_TOT_ADM_MISSING@EXAMPLE.LOCAL",
            "Group",
            samaccountname="_GGP_TOT_ADM_MISSING",
            domain="EXAMPLE.LOCAL",
        )

        report = plan_convention(self.convention, [group], [])

        self.assertEqual(report.plans, [])
        self.assertEqual(
            report.unresolved,
            [(group.name, "MISSING.EXAMPLE.LOCAL")],
        )

    def test_ambiguous_targets_are_not_planned(self):
        group = node(
            "group-sid",
            "_GGP_TOT_ADM_HOST@EXAMPLE.LOCAL",
            "Group",
            samaccountname="_GGP_TOT_ADM_HOST",
            domain="EXAMPLE.LOCAL",
        )
        targets = [
            node("computer-1", "HOST.EXAMPLE.LOCAL", "Computer"),
            node("computer-2", "HOST.EXAMPLE.LOCAL", "Computer"),
        ]

        report = plan_convention(self.convention, [group], targets)

        self.assertEqual(report.plans, [])
        self.assertEqual(len(report.ambiguous), 1)

    def test_reverse_direction_is_supported(self):
        convention = Convention(
            **{
                **self.convention.__dict__,
                "direction": "target_to_source",
            }
        )
        group = node(
            "group-sid",
            "_GGP_TOT_ADM_HOST@EXAMPLE.LOCAL",
            "Group",
            samaccountname="_GGP_TOT_ADM_HOST",
            domain="EXAMPLE.LOCAL",
        )
        computer = node("computer-sid", "HOST.EXAMPLE.LOCAL", "Computer")

        report = plan_convention(convention, [group], [computer])

        self.assertEqual(report.plans[0].from_node, computer)
        self.assertEqual(report.plans[0].to_node, group)

    def test_group_plan_is_also_created_for_direct_user_members(self):
        convention = Convention(
            **{
                **self.convention.__dict__,
                "expand_group_members": True,
            }
        )
        group = node("group-sid", "ADM_HOST", "Group")
        computer = node("computer-sid", "HOST.EXAMPLE.LOCAL", "Computer")
        alice = node("alice-sid", "ALICE@EXAMPLE.LOCAL", "User")
        original = EdgePlan(convention, group, computer, computer.name)
        report = ConventionReport(convention=convention, plans=[original])

        _expand_group_member_plans(report, {group.object_id: [alice]})

        self.assertEqual(len(report.plans), 2)
        self.assertEqual(report.plans[0], original)
        self.assertEqual(report.plans[1].from_node, alice)
        self.assertEqual(report.plans[1].to_node, computer)

    def test_duplicate_user_target_expansions_are_suppressed(self):
        convention = Convention(
            **{
                **self.convention.__dict__,
                "expand_group_members": True,
            }
        )
        first_group = node("group-1", "ADM_HOST_1", "Group")
        second_group = node("group-2", "ADM_HOST_2", "Group")
        computer = node("computer-sid", "HOST.EXAMPLE.LOCAL", "Computer")
        alice = node("alice-sid", "ALICE@EXAMPLE.LOCAL", "User")
        report = ConventionReport(
            convention=convention,
            plans=[
                EdgePlan(convention, first_group, computer, computer.name),
                EdgePlan(convention, second_group, computer, computer.name),
            ],
        )

        _expand_group_member_plans(
            report,
            {first_group.object_id: [alice], second_group.object_id: [alice]},
        )

        self.assertEqual(len(report.plans), 3)

    def test_discovery_fetches_members_for_resolved_groups(self):
        convention = Convention(
            **{
                **self.convention.__dict__,
                "expand_group_members": True,
            }
        )
        group = node(
            "group-sid",
            "_GGP_TOT_ADM_HOST@EXAMPLE.LOCAL",
            "Group",
            samaccountname="_GGP_TOT_ADM_HOST",
            domain="EXAMPLE.LOCAL",
        )
        computer = node("computer-sid", "HOST.EXAMPLE.LOCAL", "Computer")
        alice = node("alice-sid", "ALICE@EXAMPLE.LOCAL", "User")

        class Session:
            def execute_read(self, function, *args):
                if function is _fetch_nodes:
                    return [group] if args[0] == "Group" else [computer]
                if function is _fetch_direct_user_members:
                    self.requested_group_ids = args[0]
                    return {group.object_id: [alice]}
                raise AssertionError(f"Unexpected read function: {function}")

        session = Session()
        report = discover(session, convention)

        self.assertEqual(session.requested_group_ids, [group.object_id])
        self.assertEqual(
            [(plan.from_node.label, plan.to_node.label) for plan in report.plans],
            [("Group", "Computer"), ("User", "Computer")],
        )

    def test_admin_evidence_uses_bloodhound_local_group_model(self):
        group = node("group-sid", "ADM_HOST", "Group")
        computer = node(
            "computer-sid",
            "HOST.EXAMPLE.LOCAL",
            "Computer",
            domain="EXAMPLE.LOCAL",
        )
        plan = EdgePlan(self.convention, group, computer, computer.name)

        class Result:
            def single(self):
                return {"matched": 1}

            def consume(self):
                return None

        class Transaction:
            def run(self, query, **parameters):
                self.query = query
                self.parameters = parameters
                return Result()

        transaction = Transaction()
        matched = _create_admin_evidence_batch(transaction, "Group", [plan])

        self.assertEqual(matched, 1)
        self.assertIn(":Base:ADLocalGroup", transaction.query)
        self.assertIn(":LocalToComputer", transaction.query)
        self.assertIn(":MemberOfLocalGroup", transaction.query)
        self.assertNotIn("lastseen", transaction.query)
        evidence = transaction.parameters["edges"][0]
        self.assertTrue(evidence["local_group_id"].endswith("-544"))
        self.assertEqual(
            evidence["local_group_properties"]["name"],
            "ADMINISTRATORS@HOST.EXAMPLE.LOCAL",
        )
        self.assertEqual(
            evidence["edge_properties"]["inference_source"],
            "bloodhound-enrich",
        )

class ConfigurationTests(unittest.TestCase):
    def test_group_member_expansion_must_be_boolean(self):
        with self.assertRaisesRegex(ConfigurationError, "must be a boolean"):
            parse_config(
                {
                    "version": 1,
                    "conventions": [
                        {
                            "id": "test",
                            "source_label": "Group",
                            "source_property": "name",
                            "source_regex": ".*",
                            "target_label": "Computer",
                            "target_property": "name",
                            "target_template": "{source_name}",
                            "relationship": "AdminTo",
                            "expand_group_members": "true",
                        }
                    ],
                }
            )

    def test_group_member_expansion_requires_a_group_source(self):
        with self.assertRaisesRegex(ConfigurationError, "source_label is 'Group'"):
            parse_config(
                {
                    "version": 1,
                    "conventions": [
                        {
                            "id": "test",
                            "source_label": "User",
                            "source_property": "name",
                            "source_regex": ".*",
                            "target_label": "Computer",
                            "target_property": "name",
                            "target_template": "{source_name}",
                            "relationship": "AdminTo",
                            "expand_group_members": True,
                        }
                    ],
                }
            )

    def test_unknown_fields_are_rejected(self):
        with self.assertRaises(ConfigurationError):
            parse_config(
                {
                    "version": 1,
                    "conventions": [
                        {
                            "id": "test",
                            "source_label": "Group",
                            "source_property": "name",
                            "source_regex": ".*",
                            "target_label": "Computer",
                            "target_property": "name",
                            "target_template": "{source_name}",
                            "relationship": "AdminTo",
                            "typo_field": True,
                        }
                    ],
                }
            )


if __name__ == "__main__":
    unittest.main()
