import starlight from '@astrojs/starlight';
// @ts-check
import { defineConfig } from 'astro/config';

// Pagefind search and the light/dark theme picker are Starlight defaults.
// @spec SCC-DOCS-001 SCC-ARCH-001
export default defineConfig({
    integrations: [
        starlight({
            description:
                'Hardware-attested Ed25519 signing for Solana. AMD SEV-SNP, AWS Nitro Enclaves, and Intel TDX.',
            editLink: {
                baseUrl: 'https://github.com/solana-foundation/confidential-compute/edit/main/docs-site/',
            },
            lastUpdated: true,
            pagefind: true,
            sidebar: [
                {
                    items: [
                        { label: 'Introduction', slug: 'overview/introduction' },
                        { label: 'Concepts & Glossary', slug: 'overview/concepts' },
                        { label: 'Threat Model', slug: 'overview/threat-model' },
                    ],
                    label: 'Overview',
                },
                {
                    items: [
                        { label: 'Mode A — Stateful', slug: 'architecture/mode-a-stateful' },
                        { label: 'Mode B — Atomic', slug: 'architecture/mode-b-atomic' },
                    ],
                    label: 'Architecture',
                },
                {
                    items: [
                        {
                            label: 'AMD SEV-SNP vs AWS Nitro',
                            slug: 'overview/threat-model',
                        },
                        { label: 'Intel TDX', slug: 'backends/intel-tdx' },
                    ],
                    label: 'Hardware Roots',
                },
                {
                    items: [
                        { label: 'Quickstart (15 Min)', slug: 'integration/quickstart' },
                        { label: 'Rust CPI / Anchor', slug: 'integration/rust-cpi' },
                        { label: 'TypeScript SDK', slug: 'integration/typescript-sdk' },
                        { label: 'Sidecar Daemon', slug: 'deployment/sidecar' },
                    ],
                    label: 'Integration Guides',
                },
                {
                    items: [
                        {
                            label: 'Instruction Matrix',
                            slug: 'reference/instruction-matrix',
                        },
                        {
                            label: 'Governance & Trust Roots',
                            slug: 'reference/governance',
                        },
                    ],
                    label: 'API Reference',
                },
            ],
            social: [
                {
                    href: 'https://github.com/solana-foundation/confidential-compute',
                    icon: 'github',
                    label: 'GitHub',
                },
            ],
            title: 'Solana Confidential Compute',
        }),
    ],
    site: 'https://github.com/solana-foundation/confidential-compute',
});
