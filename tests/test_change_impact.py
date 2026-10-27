"""Proof that comparisons are deterministic and never masquerade as policy evaluation."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from az_policy_bridge.change_impact import analyse, to_markdown

PID = "/providers/Microsoft.Authorization/policyDefinitions/fe83a0eb-a853-422d-aac2-1bffd182c5d0"
ASSIGN = "/subscriptions/demo/providers/Microsoft.Authorization/policyAssignments/storage-tls"
INIT = "/providers/Microsoft.Authorization/policySetDefinitions/example-storage-baseline"
RULE_AUDIT = {"if": {"allOf": [{"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
                                {"field": "Microsoft.Storage/storageAccounts/minimumTlsVersion", "notEquals": "TLS1_2"}]},
              "then": {"effect": "audit"}}
RULE_DENY = {**RULE_AUDIT, "then": {"effect": "deny"}}


def make_snapshot(version="1.0.0", effect="audit", rule=None, deprecated=False, assignment_version="1.*.*",
                  assignment_mode="Default"):
    return {"definitions": [{"id": PID, "properties": {"version": version,
             "metadata": {"deprecated": deprecated}, "policyRule": rule if rule is not None else ({**RULE_AUDIT, "then": {"effect": effect}})}}],
            "assignments": [{"id": ASSIGN, "properties": {"policyDefinitionId": PID,
                              "definitionVersion": assignment_version, "enforcementMode": assignment_mode}}]}


class ChangeImpactTests(unittest.TestCase):
    def setUp(self):
        self.before = make_snapshot()
        self.after = make_snapshot(version="1.1.0", effect="deny")

    def test_detect_new_restriction(self):
        r = analyse(self.before, self.after)
        f = next(x for x in r["findings"] if x["category"] == "definitions")
        self.assertEqual(f["priority"], "priority")
        self.assertTrue(any("new literal enforcement effects: deny" in c for c in f["changes"]))
        self.assertEqual(f["related_assignment_ids"], [ASSIGN.lower()])
        self.assertIn("potentially auto-ingested", f["version_adoption"][0]["version_effect"])

    def test_major_not_auto_ingested(self):
        r = analyse(self.before, make_snapshot(version="2.0.0", effect="deny"))
        f = next(x for x in r["findings"] if x["category"] == "definitions")
        self.assertIn("outside configured major", f["version_adoption"][0]["version_effect"])

    def test_minor_pinned_not_auto_ingested(self):
        b = make_snapshot(assignment_version="1.0.*")
        a = make_snapshot(version="1.1.0", effect="deny", assignment_version="1.0.*")
        r = analyse(b, a)
        f = next(x for x in r["findings"] if x["category"] == "definitions")
        self.assertIn("outside configured minor", f["version_adoption"][0]["version_effect"])

    def test_deprecation_change(self):
        r = analyse(self.before, make_snapshot(deprecated=True))
        self.assertEqual(r["finding_count"], 1)
        self.assertTrue(any("deprecated" in x for x in r["findings"][0]["changes"]))

    def test_metadata_only_not_high_priority(self):
        r = analyse(self.before, make_snapshot(version="1.0.1"))
        self.assertEqual(r["findings"][0]["priority"], "review")

    def test_assignment_enforcement_change(self):
        r = analyse(self.before, make_snapshot(assignment_mode="DoNotEnforce"))
        f = next(x for x in r["findings"] if x["category"] == "assignments")
        self.assertIn("enforcement mode changed", f["changes"])
        self.assertEqual(f["priority"], "priority")

    def test_no_values_in_report(self):
        old = make_snapshot(); new = make_snapshot()
        old["assignments"][0]["properties"]["parameters"] = {"credential": {"value": "TOP_SECRET_A"}}
        new["assignments"][0]["properties"]["parameters"] = {"credential": {"value": "TOP_SECRET_B"}}
        r = analyse(old, new)
        text = to_markdown(r) + json.dumps(r)
        self.assertNotIn("TOP_SECRET_A", text)
        self.assertNotIn("TOP_SECRET_B", text)
        self.assertIn("parameter values changed", text)

    def test_workload_candidates_with_explicit_type_map(self):
        plan = {"resource_changes": [{"address": "azurerm_storage_account.data", "type": "azurerm_storage_account",
                                      "change": {"actions": ["create"]}},
                                     {"address": "azurerm_key_vault.secrets", "type": "azurerm_key_vault",
                                      "change": {"actions": ["create"]}}]}
        r = analyse(self.before, self.after, plan, {"azurerm_storage_account": "Microsoft.Storage/storageAccounts"})
        f = next(x for x in r["findings"] if x["category"] == "definitions")
        self.assertEqual(f["terraform_resource_candidates"], ["azurerm_storage_account.data"])
        self.assertEqual(r["workload_count"], 2)
        self.assertIn("not proven", to_markdown(r))

    def test_without_type_map_unknown_not_safely_approved(self):
        p = {"resource_changes": [{"type": "azurerm_storage_account", "address": "azurerm_storage_account.a"}]}
        r = analyse(self.before, self.after, p)
        self.assertFalse(r["findings"][0]["terraform_resource_candidates"])
        self.assertTrue(any("mapping" in x for x in r["evidence_gaps"]))

    def test_initiative_membership_propagates_assignment(self):
        before = {"definitions": self.before["definitions"],
                  "initiatives": [{"id": INIT, "properties": {"policyDefinitions": [{"policyDefinitionId": PID}]}}],
                  "assignments": [{"id": ASSIGN, "properties": {"policyDefinitionId": INIT}}]}
        after = json.loads(json.dumps(before))
        after["definitions"][0]["properties"]["policyRule"] = RULE_DENY
        r = analyse(before, after)
        self.assertTrue(r["findings"][0]["assigned_in_supplied_snapshot"])

    def test_initiative_member_change_reported(self):
        before = {"initiatives": [{"id": INIT, "properties": {"policyDefinitions": [{"policyDefinitionId": PID}]}}]}
        after = {"initiatives": [{"id": INIT, "properties": {"policyDefinitions": []}}]}
        r = analyse(before, after)
        self.assertEqual(r["findings"][0]["priority"], "priority")
        self.assertIn("(+0/-1)", r["findings"][0]["changes"][0])

    def test_non_compliant_snapshot_cannot_assert_compliance(self):
        r = analyse(self.before, self.before)
        self.assertEqual(r["finding_count"], 0)
        self.assertIn("does not establish policy compliance", to_markdown(r))

    def test_missing_assignment_inventory_reported(self):
        r = analyse({"definitions": self.before["definitions"]}, {"definitions": self.after["definitions"]})
        self.assertTrue(any("assignment inventory" in x for x in r["evidence_gaps"]))

    def test_invalid_duplicate_snapshot_ids(self):
        bad = {"definitions": self.before["definitions"] * 2}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            analyse(bad, self.after)

    def test_invalid_type_map(self):
        with self.assertRaises(ValueError):
            analyse(self.before, self.after, type_map={"azurerm": ["Microsoft.Storage/storageAccounts"]})

    def test_json_response_stable(self):
        a = analyse(self.before, self.after)
        b = analyse(self.before, self.after)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_cli_reads_and_protects_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            b, a, out = (Path(tmp) / name for name in ("before.json", "after.json", "report.json"))
            b.write_text(json.dumps(self.before)); a.write_text(json.dumps(self.after))
            cmd = [sys.executable, "-m", "az_policy_bridge", "changes", "--before", str(b),
                   "--after", str(a), "--output", str(out), "--format", "json"]
            env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
            p = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(out.read_text())["finding_count"], 1)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(cmd, env=env, capture_output=True).returncode, 3)

    def test_azure_value_wrapper(self):
        b = {"policyDefinitions": {"value": self.before["definitions"]},
             "policyAssignments": {"value": self.before["assignments"]}}
        a = {"policyDefinitions": {"value": self.after["definitions"]},
             "policyAssignments": {"value": self.after["assignments"]}}
        self.assertEqual(analyse(b, a)["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()
