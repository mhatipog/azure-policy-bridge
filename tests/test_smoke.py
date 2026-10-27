"""Small regression guard for the current snapshot-review workflow."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from az_policy_bridge.change_impact import analyse

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "change-review"


def example(name):
    return json.loads((EXAMPLES / name).read_text())


class ReviewSmokeTests(unittest.TestCase):
    def test_review_finds_relevant_change(self):
        report = analyse(example("before.json"), example("after-hypothetical.json"),
                         example("terraform-plan.minimal.json"), example("type-map.json"))
        self.assertEqual(report["finding_count"], 2)
        self.assertTrue(any(f["terraform_resource_candidates"] for f in report["findings"]))
        self.assertFalse(any("compliant" in f["guidance"].lower() for f in report["findings"]))

    def test_missing_inventory_is_not_reported_as_a_removal(self):
        old = example("before.json")
        new = example("after-hypothetical.json")
        del new["assignments"]
        report = analyse(old, new)
        self.assertEqual(report["finding_count"], 1)
        self.assertTrue(any("comparison skipped" in s for s in report["evidence_gaps"]))

    def test_values_are_not_copied_into_report(self):
        old = example("before.json")
        new = example("after-hypothetical.json")
        old["assignments"][0]["properties"]["parameters"] = {"token": {"value": "SECRET_BEFORE"}}
        new["assignments"][0]["properties"]["parameters"] = {"token": {"value": "SECRET_AFTER"}}
        output = json.dumps(analyse(old, new))
        self.assertNotIn("SECRET_BEFORE", output)
        self.assertNotIn("SECRET_AFTER", output)

    def test_idempotent_diff(self):
        same = example("before.json")
        self.assertEqual(analyse(same, same)["finding_count"], 0)

    def test_cli_json_and_private_output(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / "result.json"
            cmd = [sys.executable, "-m", "az_policy_bridge", "--before",
                   str(EXAMPLES / "before.json"), "--after",
                   str(EXAMPLES / "after-hypothetical.json"), "--format", "json",
                   "--output", str(dest)]
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
            run = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(dest.read_text())["finding_count"], 2)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            self.assertEqual(subprocess.run(cmd, env=env, capture_output=True).returncode, 3)


if __name__ == "__main__":
    unittest.main()
