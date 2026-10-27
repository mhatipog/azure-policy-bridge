# Azure Policy Bridge

**Your Terraform deployment is blocked by an Azure Policy owned by the central cloud team. Which one, why, and who can actually fix it?**

Azure Policy Bridge is a small, offline-first, **read-only** CLI for business/application teams and central cloud/platform teams (CCoE). It correlates Terraform plans with actual Azure Policy denial evidence, separates *policy denials* from *RBAC/provider/quota failures*, and creates a targeted central-cloud review packet.

It does **not** require Azure administrator access, modify assignments, grant exemptions, deploy infrastructure, or pretend to replace Azure Policy evaluation.

## Three-minute demonstration

Python 3.10+, standard library only at runtime:

```bash
python -m pip install -e .

# 1. Before deployment: limited offline check against available policy snapshots.
az-policy-bridge examples/policy-bridge/terraform-plan.json \
  --assignments examples/policy-bridge/assignments.json \
  --definitions examples/policy-bridge/definitions.json

# 2. When an AzureRM Terraform apply is denied: use the ORIGINAL error log.
az-policy-bridge examples/policy-bridge/terraform-plan.json \
  --errors examples/policy-bridge/terraform-apply.sample.txt \
  --assignments examples/policy-bridge/assignments.json \
  --output governance-review.md --fail-on confirmed
```

Also accepts structured ARM deployment error JSON in `--errors`. The examples are synthetic and include no tenant data. Test without installing: `PYTHONPATH=src python -m az_policy_bridge ...`.

## Designed for the actual ownership boundary

| Input | What the tool can establish | Who can act |
|---|---|---|
| Terraform plan JSON | Proposed changes and *advisory* suspicious settings | Business/application developer |
| Read-only policy assignments and definitions | **Possible** conflict for a small, supported subset of static `deny` rules | CCoE confirms real assignment scope, initiatives and exceptions |
| Actual Terraform `apply` error or ARM denial JSON | **Confirmed Azure policy denial**, ID, initiative reference and related resource when present | Developer adapts to approved pattern; CCoE explains or reviews policy |
| Other Azure error codes | RBAC, provider-registration or quota blocker instead of blaming Azure Policy | Identity/platform/subscription owner |
| Generated review packet | Evidence, owner hints, exception-risk questions and missing information | Design/risk decision remains with accountable humans |

**Example:** The proposed Storage account has public network access enabled. Your organization assigns a management-group policy denying public endpoints. The tool identifies the exact assignment from Azure's error, links it to the Terraform resource, suggests adapting the design to approved private connectivity, and explains why overriding the guardrail could expand data exposure. It does **not** recommend automatically disabling the policy.

**Important:** Portal and Terraform may send different API payloads. A portal success or apparently sound IaC is not proof that Terraform will pass the same policy. See [HashiCorp's real-world example](https://support.hashicorp.com/hc/en-us/articles/45170294099731-Azure-policy-blocks-Terraform-apply-while-via-the-Azure-Portal-it-works).

## Real deployment: collect evidence safely

```bash
umask 077  # private output files, especially important for JSON plans
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# After an authorized deployment attempt fails, save the relevant output
# to a private local file. Do not enable TF_LOG=TRACE by default.
az-policy-bridge tfplan.json --errors apply-error.txt \
  --output review.md --fail-on confirmed
```

`terraform show -json` may expose **sensitive values in plaintext**. Never upload an unreviewed plan, state, debug trace or Azure error log to a public repository or issue. Run this tool locally or on a trusted enterprise runner. Its report retains resource names and policy IDs, which can also be confidential; review before sharing. It intentionally discards arbitrary plan values and arbitrary error-message text.

If you have read access, enrich locally with policy assignments applicable to the target scope:

```bash
az policy assignment list --scope "/subscriptions/<subscription-id>" \
  --disable-scope-strict-match true --max-items 1000 -o json > assignments.json
```

Inspect pagination and inherited management-group scope. Ask your CCoE for a scoped export when your account cannot read assignments. Policy definitions can be supplied as a JSON array through `--definitions`; snapshot **must** include each referenced definition and initiative to support limited preflight checks. Missing data is not interpreted as compliance. More details in [deployment workflow](docs/workflow.md).

## CI usage

```bash
az-policy-bridge tfplan.json --errors azure-denial.json \
  --format json --output triage.json --fail-on confirmed
```

Exit codes: **0** = report generated with no gate condition; **2** = confirmed policy denial (or static candidate if explicitly using `--fail-on candidate`); **3** = invalid input/report failure. Without `--fail-on`, the CLI is advisory and returns 0. A 0 exit does **not** mean Azure will permit deployment.

Use `--fail-on candidate` if your organization deliberately wants uncertain static candidates to require review. Never automatically grant exemptions or weaken a policy in CI.

## What it intentionally does not do

- Claim to fully emulate Azure Policy aliases, effects, management-group inheritance, initiatives, override/selectors, or exemptions. Supported offline matches are clearly labeled **POSSIBLE**, never “confirmed”. The authoritative evaluator is Azure.
- Decide that an enterprise-wide policy is wrong or that a one-off exemption is acceptable.
- Score the residual risk numerically without workload classification or policy intent.
- Automatically deploy, scan privileged subscriptions, request exemptions or bypass guardrails.
- Reconstruct provider-side API requests exactly from Terraform plan JSON.

This tool focuses on **the smallest evidence that makes a developer/CCoE conversation productive**. The earlier [Azure Private Landing Zone Lab](https://github.com/mhatipog/azure-private-landing-zone-lab) remains a separate optional reference; it is **not** required here.

MIT licensed. Contributions welcome, especially sanitized real-world denial payloads and provider-version-specific regression tests. For bugs involving policy bypass, coordinate responsible disclosure rather than publishing exploitable tenant details.
