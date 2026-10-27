# Review changes to Azure guardrails

Azure Policy has built-in definition versioning. An assignment can deliberately select a major/minor version range; initiatives, exclusions, parameters, resource selectors, and exemptions affect what is actually enforced. A published policy change does **not** automatically mean every assigned environment will change. [Microsoft assignment documentation](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure).

This utility compares two **explicitly collected** policy snapshots and identifies questions worth investigating. It does not evaluate Azure Policy or prescribe removal of an existing control. It is designed to complement, not replace:

- [AzAdvertizer](https://www.azadvertizer.net/) for public release and alias change history.
- [Azure Governance Visualizer](https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting) for tenant governance inventory.
- [Enterprise Azure Policy as Code](https://azure.github.io/enterprise-azure-policy-as-code/) for policy deployment lifecycle.
- AzureRM preflight, Azure Policy Insights, and resource-specific testing for actual enforcement evidence.

## Fast offline demo

```bash
python -m pip install -e .
az-policy-bridge changes \
  --before examples/change-review/before.json \
  --after examples/change-review/after-hypothetical.json \
  --plan examples/change-review/terraform-plan.minimal.json \
  --type-map examples/change-review/type-map.json
```

The example uses the public Microsoft **Storage minimum-TLS policy identifier and general policy structure**, with a deliberately **hypothetical** change to demonstrate what a future review could look like. It is **not** evidence that Microsoft made the simulated change. The included Terraform plan is synthetic and contains no secrets.

## Review your own policies

Export two snapshots under an authorized, **read-only** Azure identity. For example, if your organization permits Azure CLI inventory reads, you can use the opt-in helper:

```bash
bash scripts/capture-policy-snapshot.sh before.json
# Run again after an authorized policy or catalog update:
bash scripts/capture-policy-snapshot.sh after.json
az-policy-bridge changes --before before.json --after after.json \
  --format markdown --output review.md
```

The export uses your selected Azure CLI subscription and collects assignments (including inherited scope as surfaced by the CLI), definitions, and initiatives. The helper hasn't been validated against every tenant hierarchy or Azure CLI version. Before treating any comparison as complete, verify that collection permissions and scope really include the assignments that matter. A successful query against a narrow subscription does **not** establish full inheritance or exemptions.

The `changes` command also accepts Azure CLI REST-style envelopes where each category is an object containing a `value` array. Required top-level keys are `definitions` / `policyDefinitions`, `initiatives` / `policySetDefinitions`, and `assignments` / `policyAssignments`. Missing collections are **not** interpreted as absent tenant-wide.

## Optional Terraform intersection

A Terraform JSON plan can include confidential credentials or business data, even when marked sensitive. Keep it local. The tool only reads resource **type** and **address**, not values.

For correlation, an explicit mapping is required, such as:

```json
{"azurerm_storage_account":"Microsoft.Storage/storageAccounts"}
```

This mapping only helps prioritize review of resource *types* mentioned in a policy rule. It does not prove the rule applies to those resources: type predicates can occur under `not`, `anyOf`, or conditions that do not match the deployment. No mapping or missing policy evidence means **unknown**, not approved.

## Reading findings

- **Priority**: a potentially impactful difference such as rule logic, an initiative membership change, changed assignment scope/parameters, or a new literal enforcing effect.
- **Attention**: parameter schema or deprecation change, or an inventory add/remove that might reflect incomplete collection.
- **Review**: version change without a detected semantic rule delta, or metadata change.
- **Version adoption**: only a potential consequence of a version selector (`1.*.*` versus `1.0.*`). Assignment defaults, initiative references, policy overrides, exemptions, and effective policy versions still need to be checked with Azure.

The report intentionally does **not** say whether a policy is obsolete, security is improved, or a new workload is compliant. A rule updated recently can still be inappropriate for a specific environment, and an old rule can remain essential. Reconcile against documented control objectives and current service documentation with accountable reviewers.

## Security and operational boundaries

- No admin privileges, policy write access, automatic exemptions or Azure deployment calls are needed to analyze snapshots.
- Snapshots may contain sensitive tenant metadata and parameter values. Do **not** publish them; use a private Git repository or other approved store with restricted access, retention and secret scanning.
- Report includes policy/assignment IDs and optional Terraform addresses; treat the report as potentially confidential.
- Report files use restrictive `0600` permissions and are never silently overwritten.
- `changes` deliberately returns exit code `0` when comparison completes, even if it reports a significant change. It is a **review generator, not a release approval gate**. Errors return `3`.
- Tracking changes over time requires a trusted scheduler and recorded capture timestamps; neither is inferred from filenames or JSON order.
