# Azure Policy Bridge

**Which Azure governance changes deserve your attention?**

A small, read-only CLI to compare Azure Policy inventories over time. It highlights changed rules, initiatives, assignments and version selections, then optionally points to **potentially related Terraform resources**. Built for periodic platform reviews and policy-as-code workflows; not another policy evaluator or compliance scanner.

## Try it in 30 seconds

Python 3.10+, no runtime dependencies beyond the standard library.

```bash
pip install -e .
az-policy-bridge \
  --before examples/change-review/before.json \
  --after examples/change-review/after-hypothetical.json
```

Get machine-readable findings or enrich the report with **resource-type hints** from a Terraform plan:

```bash
az-policy-bridge --before before.json --after after.json \
  --plan tfplan.json --type-map type-map.json \
  --format json --output review.json
```

The previous `az-policy-bridge changes` syntax also works. Output is advisory: **a matching resource type is not evidence that a policy applies**. Missing inventory, scope inheritance, exclusions, versions, exemptions and Azure evaluation details must still be checked. The example change is hypothetical, not an actual Microsoft policy update.

## Use with an authorized Azure subscription

```bash
bash scripts/capture-policy-snapshot.sh before.json
# Run again after policies or assignments change:
bash scripts/capture-policy-snapshot.sh after.json
az-policy-bridge --before before.json --after after.json --output review.md
```

The helper uses your Azure CLI login to read definitions, initiatives and assignments for the selected subscription. It doesn't modify cloud resources. Confirm inherited scope, privileges and inventory completeness before drawing conclusions. [Detailed workflow and limitations](docs/change-review.md).

## What you get

- **Change summaries:** rule logic, parameter defaults, initiative members, assignment settings and version selectors.
- **Review prioritization:** notable changes separated from routine version metadata, with related assignment IDs where present in the supplied inventory.
- **Optional Terraform relevance:** mapped Azure resource types and matching Terraform resource addresses. No parsing of Terraform expressions or data values.
- **Explicit unknowns:** incomplete inventories and uncertain version adoption are stated rather than silently classified as compliant.

The CLI runs offline. **Snapshots and `terraform show -json` plans can contain confidential details or secrets**; keep them on trusted machines and don't commit live tenant exports. Reports may contain policy IDs and Terraform addresses. Output files are created with restricted permissions and are never overwritten.

## Scope and ecosystem

Azure Policy, [AzAdvertizer](https://www.azadvertizer.net/), [AzGovViz](https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting) and [EPAC](https://azure.github.io/enterprise-azure-policy-as-code/) already provide evaluation, change history, estate inventory and policy lifecycle management. This tool focuses narrowly on **comparing snapshots and creating a reviewable change summary**. It cannot assess whether a policy is obsolete or recommend granting exemptions.

For contributions, prefer real-world *sanitized* snapshot pairs and verified interpretation edge cases. Run the focused smoke tests with `python -m unittest discover -s tests -v`.

MIT license. Not affiliated with Microsoft or HashiCorp.