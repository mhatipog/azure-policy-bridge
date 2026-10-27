# The practical business-team ↔ CCoE workflow

## 1. Developer: prove the proposed change, not a fantasy deployment

Produce a saved `terraform plan`, capture the `terraform show -json` locally, and note the exact target subscription/resource group. It is important to use the *same provider version and planned variables* as in the deployment that was denied. If the plan contains ephemeral credentials or data, keep the entire input and its execution on an approved enterprise machine.

Run `az-policy-bridge tfplan.json` to see obvious design advisories; these are not organization-policy findings. If permitted, obtain applicable read-only assignment/definition snapshots and run the limited offline `--assignments ... --definitions ...` check before applying. A policy initiative or unsupported Azure alias may not be statically matched: treat that as unknown.

## 2. Developer: take an actual Azure denial to the central team

When a permitted `terraform apply` is blocked, preserve only the relevant error segment in a private file. `--errors` understands AzureRM's `RequestDisallowedByPolicy` with `Policy identifiers: '[...]'` and ARM error `details` / `additionalInfo`. It extracts policy assignment ID, definition ID, initiative reference ID if available, exact Terraform address and allowlisted evaluation expressions. It recognizes AuthorizationFailed, provider-registration and quota errors as separate categories.

The report's assignment ID is often enough for CCoE to retrieve the policy text without granting the developer access to a management group. If assignment data is supplied, the report includes available description, scope and owner metadata. If it isn't supplied, **it won't invent a policy explanation**.

## 3. Joint resolution: four legitimate paths

1. **Change the workload design:** use an approved private endpoint + DNS architecture, mandated identity, allowed region, naming or logging pattern. Usually the best outcome.
2. **Use an approved platform product:** a central shared module, managed landing-zone component or supported self-service deployment path. The business developer shouldn't own hub firewall, DNS or root policy changes.
3. **Propose a scoped temporary exception:** central team verifies business need, data classification, compensating controls, exact affected resources, owner, expiry and rollback. An approval is not implied by this report.
4. **Change a centrally applied policy:** only the central owner can assess organizational blast radius, peer workloads, audit obligations and policy rollout. Not something this CLI automates.

If the issue is RBAC or missing provider registration rather than Policy, raise the correct request, not an Azure Policy exemption.

## Data-handling notes

- Terraform's `show -json` may disclose passwords, IDs and connection strings despite `sensitive_values` markings (see HashiCorp docs). Run in a private environment.
- The parser retains **only a narrow allowlist** of Boolean/short-value fields from plan JSON, Azure IDs, assignment metadata and selected non-secret evaluation expressions. It intentionally does not reproduce arbitrary Azure `message` strings or full `after` values.
- Policy assignment descriptions and metadata can themselves be confidential. Review generated reports before forwarding them beyond authorized stakeholders.
- Do not use a report as assurance that private endpoints resolve or that a workload complies after deployment. Those tests belong to separate operational acceptance processes.

## Supported static preflight subset

Simple `deny` policy definitions and initiative references (where both assignment and referenced definitions are present), with `allOf`, `anyOf`, `not`, `equals`, `notEquals`, `in`, `notIn` and selected `type`, `location`, and publicNetworkAccess aliases. Unsupported aliases, dynamic functions, selectors, overrides, enrollment mode, missing properties and ambiguous scoping are **unknown/skipped**. This is **not** faithful policy evaluation and does not prove future success.

### Authoritative background

- Azure Resource Manager [RequestDisallowedByPolicy troubleshooting](https://learn.microsoft.com/azure/azure-resource-manager/troubleshooting/error-policy-requestdisallowedbypolicy)
- Azure CLI [policy assignment listing and inherited scope](https://learn.microsoft.com/cli/azure/policy/assignment)
- Azure Policy [assignment enforcement modes](https://learn.microsoft.com/azure/governance/policy/concepts/assignment-structure)
- HashiCorp [Terraform show JSON sensitive data warning](https://developer.hashicorp.com/terraform/cli/commands/show)
- HashiCorp [Terraform vs Portal differing policy outcomes](https://support.hashicorp.com/hc/en-us/articles/45170294099731-Azure-policy-blocks-Terraform-apply-while-via-the-Azure-Portal-it-works)
