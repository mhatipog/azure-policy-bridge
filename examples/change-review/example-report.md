# Azure Policy change-impact review

*Read-only advisory comparison. Not a policy pass/fail decision.*

**2 changes** | 2 proposed Terraform resources inspected

## PRIORITY · assignments · `/subscriptions/example-subscription/providers/microsoft.authorization/policyassignments/storage-baseline`

- parameter values changed
- Related assignments in supplied inventory: `/subscriptions/example-subscription/providers/microsoft.authorization/policyassignments/storage-baseline`
- Next: Review intended control, assignment scope, effective parameters and exclusions; validate with Azure Policy before enforcing.

## PRIORITY · definitions · `/providers/microsoft.authorization/policydefinitions/fe83a0eb-a853-422d-aac2-1bffd182c5d0`

- reported definition version changed: 1.0.0 → 1.1.0
- policy rule logic changed; Azure evaluation required
- new literal enforcement effects: deny
- Related assignments in supplied inventory: `/subscriptions/example-subscription/providers/microsoft.authorization/policyassignments/storage-baseline`
- Rule type references (not proven applicability): `microsoft.storage/storageaccounts`
- Possible workload intersections: `azurerm_storage_account.data`
- Assignment `/subscriptions/example-subscription/providers/microsoft.authorization/policyassignments/storage-baseline`: potentially auto-ingested (verify overrides/exemptions)
- Next: Review intended control, assignment scope, effective parameters and exclusions; validate with Azure Policy before enforcing.

## Evidence boundaries

- Resource-type intersections are candidates only; tenant inheritance, assignments, exemptions, selectors, overrides and effective versions require verification.
