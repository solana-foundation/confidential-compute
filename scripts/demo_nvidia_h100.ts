/**
 * The former NVIDIA showcase used a local key and a public placeholder digest.
 * It did not authenticate GPU evidence, CPU/GPU binding or model execution.
 * Both legacy verifier modes now fail closed with custom error 18.
 * See docs/intent/confidential-compute-nvidia-specs.md and #320 v3 for the required adapter.
 * Keep this entrypoint free of RPC calls, key loading and transaction submission.
 */
console.error(
    'NVIDIA demo unavailable: authenticated evidence/proof enrollment is not implemented. ' +
        'The legacy measurement-only instruction is disabled (NvidiaAttestationUnavailable, custom 18).',
);
process.exitCode = 1;
