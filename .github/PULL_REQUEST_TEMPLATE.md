## What and why

<!-- What changes, and why. Link related issues. -->

## Change tier

<!-- Classify your own change (SDLC section 2). When in doubt, classify up. -->

- [ ] **Critical**: key management, auth, fund movement, upgrade authority, or onchain program logic
- [ ] **Standard**: production-facing, non-critical paths
- [ ] **Low**: non-production, zero security impact (docs, dev tooling, test fixtures)

## Threat model

<!--
Required when the change introduces or modifies a trust boundary, creates a new value-movement path, or changes who can do what. Otherwise write "N/A".

1. What is being built or changed, and what data or value does it touch?
2. What are the trust boundaries? Who can call this, and with what authority?
3. What external dependencies are introduced or changed? What happens if they fail, lie, or disappear?
4. What is the worst-case impact if this component is fully compromised?
-->

## New dependencies

<!-- List each new crate or package with a justification, or write "None". Critical-tier additions need security team acknowledgment. -->

## Critical-tier checklist

<!-- Complete for Critical changes. -->

- [ ] Account validation covers owner, signer, PDA seeds, and discriminators
- [ ] Arithmetic in program code is checked
- [ ] No `unwrap`, `expect`, or `panic` in production code
- [ ] Errors are handled explicitly, with no silent failures
- [ ] Docs are updated

## Testing

<!-- Which `just` recipes did you run (for example `just check`, `just test`)? -->

## AI disclosure

Check one. See the [AI use policy](https://github.com/solana-foundation/confidential-compute/blob/main/CONTRIBUTING.md#ai-use).

- [ ] No AI tooling was used beyond editor autocomplete.
- [ ] AI tooling was used. Tool and extent: <!-- e.g. Claude wrote the tests; I wrote the implementation -->
