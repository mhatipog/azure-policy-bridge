# A practical Azure deployment troubleshooting workflow

## 1. Diagnose with the smallest useful input

Start with the error from an authorized AzureRM apply operation, ARM deployment, Bicep deployment, or Azure CLI operation. Use `az-policy-bridge --errors deployment-error.txt` or `--errors error.json`. No cloud login is required. When diagnostics contain a Policy denial, the assignment and definition IDs are reliable *identifiers*, but they do not necessarily reveal the predicate or permitted remediation.

A failed deployment can surface multiple policy denials and independent authorization/registration failures. Do not treat a generic deployment failure as evidence of a policy violation, and do not interpret an absence of recognized denials as a successful evaluation.

## 2. Enrich only when needed

For a Terraform-based deployment, use the matching saved plan (`terraform show -json`) only in a private environment. If you have authorized access, obtain the assigned policy and its definitions. A snapshot can be incomplete, stale, or miss inherited management-group assignments. Azure's evaluation remains authoritative.

Use the assignment ID to retrieve relevant configuration via a read-only account, or ask the appropriate policy owner to supply the evaluation details. Check effective policy parameters, exclusions, resource selectors, initiative definition references, exemption scope and provider/API-version differences. Different deployment interfaces can send different intermediate payloads.

## 3. Choose a resolution route

- **Adapt configuration:** deploy with an allowed region, network model, identity, storage setting or other documented option.
- **Use a supported deployment path:** use a shared module or service configured for this environment, when available.
- **Investigate request-level differences:** compare provider version, actual requested properties and evaluation details; do not assume the final declared configuration is what Azure evaluated.
- **Request policy review:** include relevant assignment/definition IDs, exact resource scope, technical requirement, alternatives attempted and the unresolved question. A deviation—if ever allowed—needs accountable review and controls, not an automatic CLI action.
- **Investigate a different cause:** identity/RBAC, provider registration and quotas have different owners and fixes.

## 4. Trust and privacy rules

1. Avoid publishing raw Terraform plans, state files, full trace logs or operational tenant identifiers.
2. Capture the minimum evidence needed and keep generated files in private storage.
3. Interpret `POSSIBLE_POLICY_CONFLICT_NOT_AZURE_VERIFIED` as an advisory candidate, not a failed Azure evaluation.
4. Confirm each recommended change with the assigned policy's actual intent, target scope, allowed pattern and service capability.
5. Never infer that a missing match means that the deployment will succeed.

## Static policy matching limits

The optional local matcher supports a small subset of `deny` conditions involving simple `type`, `location` and selected public network access aliases, `allOf`, `anyOf`, `not`, `equals`, `notEquals`, `in` and `notIn`. It does not reproduce Azure Policy functions, all field aliases, requests, managed-group inheritance, exemptions, resource selectors, or provider-specific payloads.

**References:** [RequestDisallowedByPolicy](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/error-policy-requestdisallowedbypolicy), [Policy assignment scope](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/scope), [Terraform AzureRM preflight](https://registry.terraform.io/providers/hashicorp/Azurerm/latest/docs/guides/preflight_validation), [Terraform plan secrets](https://developer.hashicorp.com/terraform/cli/commands/show).
