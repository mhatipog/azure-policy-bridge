"""Golden and adversarial fixtures for error-first deployment diagnosis."""
from __future__ import annotations
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from az_policy_bridge.cli import main
from az_policy_bridge.core import triage
from az_policy_bridge.report import markdown, json_report
from az_policy_bridge.terraform_log import extract_policy_identifiers, parse_terraform_log

FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "policy-bridge"


class DiagnosticExperienceTests(unittest.TestCase):
    def test_error_only_terraform_message(self):
        raw = (FIXTURES / "terraform-apply.sample.txt").read_text()
        result = triage(None, parse_terraform_log(raw))
        self.assertEqual(result["verdict"], "CONFIRMED_POLICY_BLOCKERS")
        self.assertEqual(len(result["changes"]), 0)
        self.assertEqual(result["confirmed_policy_denials"][0]["address_evidence"], "error_log")
        self.assertTrue(any("No Terraform plan" in g for g in result["evidence_gaps"]))

    def test_error_only_arm_message(self):
        errors = json.loads((FIXTURES / "arm-message-only.json").read_text())
        result = triage(azure_errors=errors)
        self.assertEqual(len(result["confirmed_policy_denials"]), 1)
        self.assertIn("restrict-storage", result["confirmed_policy_denials"][0]["assignment_id"])
        self.assertFalse(result["other_azure_errors"])

    def test_arm_multiple_identifiers_same_message(self):
        sample = json.loads((FIXTURES / "arm-message-only.json").read_text())
        detail = sample["error"]["details"][0]
        detail["message"] = 'Policy identifiers: ' + json.dumps([
            {"policyAssignment":{"id":"/providers/Microsoft.Authorization/policyAssignments/alpha"},
             "policyDefinition":{"id":"/providers/Microsoft.Authorization/policyDefinitions/alpha"}},
            {"policyAssignment":{"id":"/providers/Microsoft.Authorization/policyAssignments/beta"},
             "policyDefinition":{"id":"/providers/Microsoft.Authorization/policyDefinitions/beta"}},
        ])
        r = triage(azure_errors=sample)
        self.assertEqual(len(r["confirmed_policy_denials"]), 2)

    def test_arm_malformed_or_non_array_identifiers_untrusted(self):
        sample = json.loads((FIXTURES / "arm-message-only.json").read_text())
        sample["error"]["details"][0]["message"] = 'Policy identifiers: {"token":"PLEASE_HIDE"}'
        r = triage(azure_errors=sample)
        self.assertEqual(len(r["confirmed_policy_denials"]), 1)
        self.assertIsNone(r["confirmed_policy_denials"][0]["assignment_id"])
        self.assertNotIn("PLEASE_HIDE", json_report(r))

    def test_policy_log_secret_after_marker_not_repeated(self):
        raw = (FIXTURES / "terraform-apply.sample.txt").read_text() + "\napi_key=NEVER_EMIT_KEY\n"
        output = json_report(triage(azure_errors=parse_terraform_log(raw)))
        self.assertNotIn("NEVER_EMIT_KEY", output)

    def test_duplicate_identifiers_in_one_message_only_one_finding(self):
        text = 'Policy identifiers: ' + json.dumps([{
            "policyAssignment": {"id": "/providers/Microsoft.Authorization/policyAssignments/demo"},
            "policyDefinition": {"id": "/providers/Microsoft.Authorization/policyDefinitions/demo"}
        }])
        self.assertEqual(len(extract_policy_identifiers(text + " " + text)), 1)

    def test_invalid_policy_id_not_emitted(self):
        text = 'Policy identifiers: ' + json.dumps([{"policyAssignment": {
            "id": "/providers/Microsoft.Authorization/policyAssignments/good?access_token=BAD"},
            "policyDefinition": {"id": "/providers/Microsoft.Authorization/policyDefinitions/clean"}}])
        result = extract_policy_identifiers(text)
        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0]["policyAssignmentId"])
        self.assertNotIn("BAD", str(result))

    def test_non_policy_error_without_plan(self):
        errors = {"error": {"code": "AuthorizationFailed", "message": "secret: PRIVATE_VALUE"}}
        result = triage(azure_errors=errors)
        self.assertEqual(result["verdict"], "OTHER_AZURE_BLOCKERS")
        self.assertNotIn("PRIVATE_VALUE", markdown(result))

    def test_unclassified_code_retained_but_not_message(self):
        result = triage(azure_errors={"error": {"code": "UnknownDeploymentIssue", "message": "token=HIDDEN"}})
        self.assertEqual(result["verdict"], "UNCLASSIFIED_AZURE_ERRORS")
        self.assertEqual(result["unclassified_azure_errors"][0]["code"], "UnknownDeploymentIssue")
        self.assertNotIn("HIDDEN", json_report(result))

    def test_cli_error_only_json_output(self):
        with redirect_stdout(io.StringIO()) as output:
            rc = main(["--errors", str(FIXTURES / "arm-message-only.json"), "--format", "json", "--fail-on", "confirmed"])
        self.assertEqual(rc, 2)
        self.assertEqual(len(json.loads(output.getvalue())["confirmed_policy_denials"]), 1)

    def test_cli_terraform_log_stdin(self):
        raw = (FIXTURES / "terraform-apply.sample.txt").read_text()
        with patch("sys.stdin", io.StringIO(raw)), redirect_stdout(io.StringIO()) as output:
            rc = main(["--errors", "-", "--format", "json"])
        self.assertEqual(rc, 0)
        self.assertEqual(len(json.loads(output.getvalue())["confirmed_policy_denials"]), 1)

    def test_cli_ambiguous_stdin_rejected(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["-", "--errors", "-"]), 3)

    def test_cli_report_kept_private_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "result.md"
            rc = main(["--errors", str(FIXTURES / "arm-message-only.json"), "--output", str(target)])
            self.assertEqual(rc, 0)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--errors", str(FIXTURES / "arm-message-only.json"), "--output", str(target)]), 3)

    def test_plan_preflight_without_error_is_not_success_proof(self):
        with redirect_stdout(io.StringIO()) as output:
            rc = main([str(FIXTURES / "terraform-plan.json"), "--format", "json"])
        r = json.loads(output.getvalue())
        self.assertEqual(rc, 0)
        self.assertEqual(r["verdict"], "UNVERIFIED_NO_DENIAL_EVIDENCE")
        self.assertIn("No Azure deployment evidence", " ".join(r["evidence_gaps"]))


if __name__ == "__main__":
    unittest.main()
