# Documentation portal (`docs-site/`)

Local Astro Starlight site for Solana Confidential Compute.

The site is built on the workstation. `bun run build` writes `dist/`. `dist/` is gitignored.

```bash
cd docs-site
bun install
bun run dev
```

The dev server listens on `http://localhost:4321`. Pagefind search is enabled in `astro.config.mjs`.

| Command | Action |
| :--- | :--- |
| `bun install` | Install Astro, Starlight, and `sharp`. |
| `bun run dev` | Dev server at `http://localhost:4321`. |
| `bun run build` | Static build in `dist/`. |
| `bun run preview` | Serve `dist/`. |

Content files include:

```
docs-site/
├── astro.config.mjs
├── src/content.config.ts
└── src/content/docs/
    ├── index.mdx
    ├── architecture/mode-a-stateful.md
    ├── architecture/mode-b-atomic.md
    ├── deployment/sidecar.md
    ├── integration/rust-cpi.md
    ├── integration/typescript-sdk.md
    ├── overview/introduction.md
    ├── overview/threat-model.md
    ├── reference/governance.md
    └── reference/instruction-matrix.md
```

Module READMEs in `crates/`, `bins/`, `programs/`, and `sdks/typescript/` are the API references for those packages. This site is the narrative portal.
