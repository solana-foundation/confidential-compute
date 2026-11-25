// Standard TypeScript formatter config for new Solana Foundation repositories.
// Uses the shared Oxfmt style from @solana-config/oxc (fast, Rust-based).
//
// Install:
//   pnpm add -D @solana-config/oxc oxfmt
//
// Oxfmt has no `extends` mechanism, so spread the shared config into your own
// defineConfig({...}).

import solanaFmt from '@solana-config/oxc/oxfmt';
import { defineConfig } from 'oxfmt';

export default defineConfig({ ...solanaFmt });
