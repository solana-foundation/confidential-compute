// Standard TypeScript linter config for new Solana Foundation repositories.
// Uses the shared Oxlint rules from @solana-config/oxc (fast, Rust-based).
//
// Install:
//   pnpm add -D @solana-config/oxc oxlint oxlint-tsgolint
//   (drop oxlint-tsgolint if you are not enabling options.typeAware)
//
// options.typeAware and ignorePatterns are root-config-only in Oxlint and
// cannot be inherited via `extends`, so set them here in your own config.

import { defineConfig } from 'oxlint';

import solanaConfig from '@solana-config/oxc/oxlint';

export default defineConfig({
    extends: [solanaConfig],
    // Requires the `oxlint-tsgolint` devDependency; remove this line if opting out.
    options: { typeAware: true },
});
