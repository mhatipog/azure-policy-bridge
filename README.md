# Azure Policy Bridge

**Understand why an Azure deployment was rejected, and what to try next.**

An offline, read-only Python CLI that extracts evidence from Azure deployment failures and produces a concise, reviewable diagnosis. It works with **Terraform apply output** and **ARM/Bicep deployment errors**. A Terraform plan and policy snapshots are optional context—not prerequisites for getting an answer.

No Azure credentials, dashboard, agent, tenant-wide permissions, or cloud resources are required for local analysis. The tool never edits policies, grants exemptions, or deploys anything.

## Quick start: start with the error

Requires Python 3.10+; no runtime packages beyond the standard library.

```bash
python -m pip install -e .

# Terraform / AzureRM apply output (text)
az-policy-bridge --errors examples/policy-bridge/terraform-apply.sample.txt

# Structured ARM / Bicep deployment failure (JSON)
az-policy-bridge --errors examples/policy-bridge/azure-denial.json

# Paste a short diagnostic from stdin; Ctrl-D to finish on Unix
az-policy-bridge --errors -
```

The output answers:

- **What is confirmed?** A denied Azure Policy, a separate authorization/provider/quota error, or insufficient diagnostic evidence.
- **What can be identified?** Policy assignment/definition IDs, initiative reference, optional resource ID, Terraform resource address, and allowlisted policy evaluation values.
- **What's the next step?** Inspect the assigned policy and its parameters, adapt the deployment where supported, or send a narrowly scoped question to the relevant policy owner.
- **What is uncertain?** A denial code alone doesn't reveal the exact violated condition; an offline plan cannot prove what Azure will accept.

## Add more context when you have it

```bash
# Terraform plan JSON can contain plaintext secrets; keep it local.
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

az-policy-bridge tfplan.json \
  --errors examples/policy-bridge/terraform-apply.sample.txt \
  --assignments examples/policy-bridge/assignments.json \
  --format json --output diagnosis.json --fail-on confirmed

# Limited advisory preflight using an explicit assignment and definition export.
az-policy-bridge tfplan.json \
  --assignments examples/policy-bridge/assignments.json \
  --definitions examples/policy-bridge/definitions.json
```

The code distinguishes **confirmed Azure errors**, **observations from the plan**, and **possible static policy matches**. These evidence levels are never interchangeable. In particular, unknown policy aliases, exemptions, selectors, effective scope or provider request payloads are **not** assumed compliant.

### How the diagnosis works

| Evidence available | Interpretation | Next action |
|---|---|---|
| Only an AzureRM or ARM/Bicep failure | Extract confirmed error codes and policy IDs when provided | Resolve the identified rule or investigate missing evaluation detail |
| Additional Terraform plan | Correlate resources; flag selected configuration settings separately | Check if an allowed configuration resolves the conflict |
| Policy assignment snapshot | Add the applicable assignment's supplied name/scope and available contact metadata | Confirm parameters, exemptions, inherited scope and required controls |
| Policy definitions plus a plan | Limited offline candidate matching of known, simple `deny` rules | Verify candidates with Azure; a non-match is not approval |
| Authorization, quota or registration error | Distinguish from Azure Policy | Investigate the appropriate permission or service limitation |

### Automation

```bash
az-policy-bridge --errors azure-error.json \
  --format json --output report.json --fail-on confirmed
```

Exit code **0** means reporting succeeded without the selected gate condition; **2** means a confirmed policy denial (or an advisory candidate if `--fail-on candidate`); **3** is an input or report error. **Exit 0 never certifies deployment success or policy compliance.** Reports are created with mode `0600` and existing files are not overwritten. The tool does not send data to any endpoint.

## Data and trust boundaries

**Terraform plan JSON and error logs may contain credentials, connection strings, resource names, account IDs or confidential policy identifiers.** Run locally or on a trusted runner, keep input files private, and review the diagnosis before distributing it. The parser never reproduces arbitrary error messages or Terraform `before`/`after` objects; it only retains a narrow set of diagnostic fields. Resource addresses, Azure IDs and policy metadata are still potentially confidential.

The tool does **not** recreate Azure Policy evaluation, suggest automatic exemptions, decide residual risk, change access controls, or guarantee a Terraform/API provider will send the same request as another deployment interface. Read [workflow and limitations](docs/workflow.md).

## How to contribute

Useful contributions include **sanitized, reproducible AzureRM or ARM/Bicep errors** with independently verified explanations; tests for new diagnostic shapes; and documentation of accepted deployment patterns. Keep tenant identifiers, real policy names, tokens and full plans out of public issues. The fixtures in this project are synthetic.

Run tests: `PYTHONPATH=src python -m unittest discover -s tests -v`.

**References:** [Azure Policy denial troubleshooting](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-policy-requestdisallowedbypolicy) · [Azure Policy scope and exemptions](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/scope) · [AzureRM preflight validation](https://registry.terraform.io/providers/hashicorp/Azurerm/latest/docs/guides/preflight_validation) · [Terraform show sensitive data](https://developer.hashicorp.com/terraform/cli/commands/show).

MIT licensed. Not affiliated with Microsoft or HashiCorp.
