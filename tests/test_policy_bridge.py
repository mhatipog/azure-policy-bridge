"""Integration and adversarial tests for the business/cloud-governance boundary."""
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from az_policy_bridge.core import parse_plan, triage
from az_policy_bridge.preflight import find_candidates
from az_policy_bridge.report import json_report, markdown
from az_policy_bridge.cli import main
from az_policy_bridge.terraform_log import parse_terraform_log

ROOT = Path(__file__).resolve().parents[1] / "examples" / "policy-bridge"

def fixture(name):
    return json.loads((ROOT / name).read_text())

class PolicyBridgeTests(unittest.TestCase):
    def setUp(self):
        self.plan = fixture("terraform-plan.json")
        self.errors = fixture("azure-denial.json")
        self.assignments = fixture("assignments.json")
        self.definitions = fixture("definitions.json")

    def test_exact_confirmed_denial_and_rbac_split(self):
        result = triage(self.plan, self.errors, self.assignments)
        self.assertEqual(result["verdict"], "CONFIRMED_POLICY_BLOCKERS")
        self.assertEqual(len(result["confirmed_policy_denials"]), 1)
        self.assertEqual(len(result["other_azure_errors"]), 1)
        self.assertEqual(result["other_azure_errors"][0]["category"], "Identity/RBAC")

    def test_unique_terraform_match_by_type_name(self):
        r = triage(self.plan, self.errors)
        self.assertEqual(r["confirmed_policy_denials"][0]["terraform_address"], "azurerm_storage_account.prototype")

    def test_assignment_ownership_and_noncompliance(self):
        r = triage(self.plan, self.errors, self.assignments)["confirmed_policy_denials"][0]
        self.assertEqual(r["governance_owner"], "Central Azure Platform")
        self.assertIn("private network", r["non_compliance_message"].lower())

    def test_output_contains_no_plan_secret_or_error_message(self):
        r = triage(self.plan, self.errors, self.assignments)
        for output in (json_report(r), markdown(r)):
            self.assertNotIn("NEVER_PUBLISH_THIS_CREDENTIAL", output)
            self.assertNotIn("DO_NOT_LEAK", output)
            self.assertNotIn("The user does not have authorization", output)

    def test_missing_errors_is_not_azure_policy_clearance(self):
        r = triage(self.plan)
        self.assertEqual(r["verdict"], "UNVERIFIED_NO_DENIAL_EVIDENCE")
        self.assertEqual(len(r["confirmed_policy_denials"]), 0)
        self.assertTrue(r["evidence_gaps"])

    def test_unrelated_azure_blocker_not_mislabeled_policy(self):
        r = triage(self.plan, {"error":{"code":"LinkedAuthorizationFailed", "message":"secret"}})
        self.assertEqual(r["verdict"], "OTHER_AZURE_BLOCKERS")
        self.assertFalse(r["confirmed_policy_denials"])

    def test_safe_terraform_advisories_are_not_confirmed_policy(self):
        r = triage(self.plan)
        self.assertEqual(r["terraform_advisories"][0]["status"], "ADVISORY")
        self.assertEqual(r["terraform_advisories"][0]["signal"], "Public network access")

    def test_unknown_plan_property_not_auto_assumed_compliant(self):
        p = copy.deepcopy(self.plan)
        p["resource_changes"][0]["change"]["after"].pop("public_network_access_enabled")
        p["resource_changes"][0]["change"]["after_unknown"]["public_network_access_enabled"] = True
        r = triage(p)
        self.assertFalse(any(x["signal"] == "Public network access" for x in r["terraform_advisories"]))

    def test_unparseable_plan_rejected(self):
        with self.assertRaises(ValueError):
            parse_plan({"planned_values": {}})

    def test_noop_excluded(self):
        p = copy.deepcopy(self.plan)
        p["resource_changes"][0]["change"]["actions"] = ["no-op"]
        self.assertEqual(len(parse_plan(p)), 1)

    def test_name_ambiguity_does_not_match(self):
        p = copy.deepcopy(self.plan)
        dup = copy.deepcopy(p["resource_changes"][0]); dup["address"] = "module.other.azurerm_storage_account.prototype"
        p["resource_changes"].append(dup)
        self.assertIsNone(triage(p, self.errors)["confirmed_policy_denials"][0]["terraform_address"])

    def test_allowlisted_evaluations_only(self):
        e = copy.deepcopy(self.errors)
        expressions = e["error"]["details"][0]["additionalInfo"][0]["info"]["evaluationDetails"]["evaluatedExpressions"]
        expressions.append({"path":"Microsoft.Foo/secrets/clientKey", "expressionValue":"password==SECRET"})
        result = triage(self.plan, e)
        self.assertEqual(len(result["confirmed_policy_denials"][0]["evaluation_evidence"]), 1)
        self.assertNotIn("password==SECRET", json_report(result))

    def test_local_preflight_supports_known_field_rule(self):
        matches, gaps = find_candidates(parse_plan(self.plan), self.assignments, self.definitions)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["status"], "POSSIBLE_POLICY_CONFLICT_NOT_AZURE_VERIFIED")

    def test_local_preflight_not_a_confirmation(self):
        self.assertEqual(triage(self.plan)["verdict"], "UNVERIFIED_NO_DENIAL_EVIDENCE")
        matches, _ = find_candidates(parse_plan(self.plan), self.assignments, self.definitions)
        self.assertEqual(len(matches), 1)

    def test_static_mismatch_no_candidate(self):
        p = copy.deepcopy(self.plan)
        p["resource_changes"][0]["change"]["after"]["public_network_access_enabled"] = False
        matches, _ = find_candidates(parse_plan(p), self.assignments, self.definitions)
        self.assertEqual(matches, [])

    def test_do_not_enforce_not_a_predicted_blocker(self):
        a = copy.deepcopy(self.assignments)
        a[0]["properties"]["enforcementMode"] = "DoNotEnforce"
        matches, _ = find_candidates(parse_plan(self.plan), a, self.definitions)
        self.assertEqual(matches, [])

    def test_overrides_skipped_not_guessed(self):
        a = copy.deepcopy(self.assignments)
        a[0]["properties"]["overrides"] = [{"kind":"policyEffect", "value":"audit"}]
        matches, gaps = find_candidates(parse_plan(self.plan), a, self.definitions)
        self.assertEqual(matches, [])
        self.assertTrue(any("overrides" in x for x in gaps))

    def test_initiative_unsupported_without_lying(self):
        d = copy.deepcopy(self.definitions)
        d[0]["properties"].pop("policyRule")
        matches, gaps = find_candidates(parse_plan(self.plan), self.assignments, d)
        self.assertEqual(matches, [])
        self.assertTrue(any("initiative" in x for x in gaps))

    def test_not_scopes_excludes_matching_resource(self):
        p = copy.deepcopy(self.plan)
        rid = self.errors["error"]["details"][0]["target"]
        p["resource_changes"][0]["change"]["before"] = {"id": rid}
        a = copy.deepcopy(self.assignments)
        a[0]["properties"]["notScopes"] = [rid]
        matches, _ = find_candidates(parse_plan(p), a, self.definitions)
        self.assertEqual(matches, [])

    def test_unknown_alias_fails_to_determine_candidate(self):
        d = copy.deepcopy(self.definitions)
        d[0]["properties"]["policyRule"]["if"]["allOf"][1]["field"] = "Microsoft.Storage/storageAccounts/aHypotheticalField"
        matches, gaps = find_candidates(parse_plan(self.plan), self.assignments, d)
        self.assertFalse(matches)
        self.assertTrue(gaps)

    def test_cli_exit_code_and_report_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "ticket.md"
            err = io.StringIO()
            with redirect_stderr(err):
                rc = main([str(ROOT / "terraform-plan.json"), "--errors", str(ROOT / "azure-denial.json"),
                           "--assignments", str(ROOT / "assignments.json"),
                           "--output", str(output), "--fail-on", "confirmed"])
            self.assertEqual(rc, 2)
            self.assertIn("Business developer", output.read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(main([str(ROOT / "terraform-plan.json"), "--output", str(output)]), 3)

    def test_cli_preflight_outputs_possible_not_confirmed(self):
        with redirect_stdout(io.StringIO()) as out:
            rc = main([str(ROOT / "terraform-plan.json"), "--assignments", str(ROOT / "assignments.json"),
                       "--definitions", str(ROOT / "definitions.json"), "--format", "json"])
        parsed = json.loads(out.getvalue())
        self.assertEqual(rc, 0)
        self.assertEqual(len(parsed["preflight_candidates"]), 1)
        self.assertEqual(parsed["verdict"], "UNVERIFIED_NO_DENIAL_EVIDENCE")

    def test_actual_terraform_stderr_parsing(self):
        log = (ROOT / "terraform-apply.sample.txt").read_text()
        parsed = parse_terraform_log(log)
        result = triage(self.plan, parsed, self.assignments)
        self.assertEqual(result["verdict"], "CONFIRMED_POLICY_BLOCKERS")
        self.assertEqual(result["confirmed_policy_denials"][0]["terraform_address"], "azurerm_storage_account.prototype")
        self.assertIn("deny-public-storage", result["confirmed_policy_denials"][0]["assignment_id"])

    def test_terraform_log_secrets_not_repeated(self):
        log = (ROOT / "terraform-apply.sample.txt").read_text() + "\nclient_secret=SENSITIVE_DO_NOT_PRINT\n"
        out = json_report(triage(self.plan, parse_terraform_log(log)))
        self.assertNotIn("SENSITIVE_DO_NOT_PRINT", out)

    def test_policy_log_multiple_policy_assignments(self):
        log = (ROOT / "terraform-apply.sample.txt").read_text()
        # Inject a separate second Error block to ensure duplicate/multiple handling.
        log += "\n" + log.replace("deny-public-storage", "require-tags")
        result = triage(self.plan, parse_terraform_log(log))
        self.assertEqual(len(result["confirmed_policy_denials"]), 2)

    def test_azure_status_message_nested_json(self):
        nested = {"value": [{"properties":{"statusMessage": json.dumps(self.errors)}}]}
        result = triage(self.plan, nested)
        self.assertEqual(len(result["confirmed_policy_denials"]), 1)

    def test_cli_accepts_terraform_log(self):
        with redirect_stdout(io.StringIO()) as output:
            rc = main([str(ROOT / "terraform-plan.json"), "--errors", str(ROOT / "terraform-apply.sample.txt"), "--format", "json", "--fail-on", "confirmed"])
        self.assertEqual(rc, 2)
        self.assertEqual(len(json.loads(output.getvalue())["confirmed_policy_denials"]), 1)

    def test_initiative_reference_match_is_only_provisional(self):
        a = copy.deepcopy(self.assignments)
        a[0]["properties"]["policyDefinitionId"] = "/providers/Microsoft.Authorization/policySetDefinitions/data-platform-baseline"
        initiative = {"id": a[0]["properties"]["policyDefinitionId"], "properties": {
            "policyDefinitions": [{"policyDefinitionId": self.definitions[0]["id"],
                                   "policyDefinitionReferenceId": "storagePublicAccess"}]}}
        candidates, gaps = find_candidates(parse_plan(self.plan), a, self.definitions + [initiative])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["initiative_reference_id"], "storagePublicAccess")

    def test_terraform_log_multiple_identifiers_in_one_error(self):
        text = (ROOT / "terraform-apply.sample.txt").read_text()
        marker = "}}]'."
        second = {"policyAssignment": {"name": "Extra guardrail", "id": "/providers/Microsoft.Management/managementGroups/corp-root/providers/Microsoft.Authorization/policyAssignments/deny-tags"},
                  "policyDefinition": {"name": "Tags", "id": "/providers/Microsoft.Authorization/policyDefinitions/deny-tags"}}
        self.assertIn(marker, text)
        text = text.replace(marker, "}}," + json.dumps(second, separators=(",", ":")) + "]'.")
        result = triage(self.plan, parse_terraform_log(text))
        self.assertEqual(len(result["confirmed_policy_denials"]), 2)

    def test_guard_against_file_size_overflow(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "large.json"
            with p.open("wb") as fp:
                fp.truncate(26_000_000)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(p)]), 3)

if __name__ == "__main__":
    unittest.main()
