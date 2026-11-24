/**
 * AWS Nitro Enclaves TypeScript SDK builders.
 *
 * @spec SCC-NITRO-008 SCC-SDK-002 SCC-SEC-005
 */
const assert = require("node:assert/strict");
const test = require("node:test");
const { sha256 } = require("@noble/hashes/sha256");
const {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_CLOCK_PUBKEY,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SYSVAR_SLOT_HASHES_PUBKEY,
  TransactionInstruction,
} = require("@solana/web3.js");
const {
  MAX_NITRO_DOCUMENT_LEN,
  NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER,
  PACKET_DATA_SIZE,
  PacketTooLargeError,
  SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID,
  VERIFY_NITRO_ATTESTATION_DISCRIMINATOR,
  VERIFY_NITRO_ATTESTATION_HEADER_LEN,
  VERIFY_NITRO_MODE_A,
  VERIFY_NITRO_MODE_B,
  buildVerifyNitroAttestationIx,
  buildVerifyNitroAttestationTx,
  computeCommitment,
  deriveBackendPolicyPda,
  derivePolicyRegistryPda,
  deriveSignerPda,
  deriveUsedNoncePdaForSource,
  deriveLegacyUsedNoncePda,
} = require("../dist/index.js");
const {
  buildVerifyNitroAttestationIxOversized,
  buildVerifyNitroAttestationTxOversized,
} = require("../dist/internal/oversized.js");

function sampleDoc(len) {
  const document = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    document[i] = i & 0xff;
  }
  return document;
}

function readU64Le(data, offset) {
  const copy = data.slice(offset, offset + 8);
  return new DataView(copy.buffer, copy.byteOffset, 8).getBigUint64(0, true);
}

function readU32Le(data, offset) {
  const copy = data.slice(offset, offset + 4);
  return new DataView(copy.buffer, copy.byteOffset, 4).getUint32(0, true);
}

function consumerIx(payer) {
  return new TransactionInstruction({
    programId: PublicKey.unique(),
    keys: [{ pubkey: payer, isSigner: true, isWritable: true }],
    data: Buffer.from([1, 2, 3]),
  });
}

test("nitro discriminator matches sha256(global:verify_nitro_attestation)[..8]", () => {
  const preimage = new TextEncoder().encode("global:verify_nitro_attestation");
  const disc = sha256(preimage).slice(0, 8);
  assert.deepEqual(
    Array.from(VERIFY_NITRO_ATTESTATION_DISCRIMINATOR),
    Array.from(disc),
  );
  assert.deepEqual(Array.from(VERIFY_NITRO_ATTESTATION_DISCRIMINATOR), [
    107, 76, 178, 169, 215, 146, 23, 95,
  ]);
  assert.equal(VERIFY_NITRO_MODE_A, 0);
  assert.equal(VERIFY_NITRO_MODE_B, 1);
});

test("Mode A instruction packs the on-chain header and account order", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const nonce = new Uint8Array(32).fill(0x55);
  const actionHash = new Uint8Array(32).fill(0x11);
  const document = sampleDoc(64);
  const nonceSlot = 95n;
  const ix = buildVerifyNitroAttestationIxOversized(
    payer,
    workload,
    VERIFY_NITRO_MODE_A,
    nonceSlot,
    actionHash,
    document,
    nonce,
  );

  assert.ok(ix.programId.equals(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID));
  assert.equal(ix.data.length, VERIFY_NITRO_ATTESTATION_HEADER_LEN + document.length);
  assert.deepEqual(
    Array.from(ix.data.subarray(0, 8)),
    Array.from(VERIFY_NITRO_ATTESTATION_DISCRIMINATOR),
  );
  assert.equal(ix.data[8], VERIFY_NITRO_MODE_A);
  assert.equal(readU64Le(ix.data, 9), nonceSlot);
  assert.deepEqual(Array.from(ix.data.subarray(17, 49)), Array.from(actionHash));
  assert.equal(readU32Le(ix.data, 49), document.length);
  assert.deepEqual(Array.from(ix.data.subarray(53)), Array.from(document));

  const [policyRegistry] = derivePolicyRegistryPda();
  const [attestedSigner] = deriveSignerPda(workload);
  const [usedNonce] = deriveUsedNoncePdaForSource(2, workload, nonce);
  assert.equal(ix.keys.length, 10);
  assert.ok(ix.keys[7].pubkey.equals(workload));
  assert.equal(ix.keys[7].isSigner, true);
  assert.ok(ix.keys[8].pubkey.equals(deriveBackendPolicyPda(2)[0]));
  assert.deepEqual([ix.keys[8].isSigner, ix.keys[8].isWritable], [false, false]);
  assert.ok(ix.keys[9].pubkey.equals(deriveLegacyUsedNoncePda(workload, nonce)[0]));
  assert.deepEqual([ix.keys[9].isSigner, ix.keys[9].isWritable], [false, false]);
  assert.ok(ix.keys[0].pubkey.equals(payer) && ix.keys[0].isSigner && ix.keys[0].isWritable);
  assert.ok(ix.keys[1].pubkey.equals(policyRegistry) && !ix.keys[1].isWritable);
  assert.ok(ix.keys[2].pubkey.equals(attestedSigner) && ix.keys[2].isWritable);
  assert.ok(ix.keys[3].pubkey.equals(usedNonce) && ix.keys[3].isWritable);
  assert.ok(ix.keys[4].pubkey.equals(SYSVAR_SLOT_HASHES_PUBKEY));
  assert.ok(ix.keys[5].pubkey.equals(SYSVAR_CLOCK_PUBKEY));
  assert.ok(ix.keys[6].pubkey.equals(SystemProgram.programId));
  assert.ok(ix.keys[7].pubkey.equals(workload) && ix.keys[7].isSigner && !ix.keys[7].isWritable);
  assert.ok(ix.keys[8].pubkey.equals(deriveBackendPolicyPda(2)[0]) && !ix.keys[8].isSigner && !ix.keys[8].isWritable);
});

test("Mode B instruction adds the instructions sysvar and uses the dummy signer", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const slotHash = new Uint8Array(32).fill(0x44);
  const actionHash = new Uint8Array(32).fill(0x22);
  const consumer = PublicKey.unique();
  const commitment = computeCommitment(slotHash, actionHash, consumer);
  const document = sampleDoc(80);
  const ix = buildVerifyNitroAttestationIxOversized(
    payer,
    workload,
    1n,
    120,
    actionHash,
    document,
    commitment,
  );

  assert.equal(ix.data[8], VERIFY_NITRO_MODE_B);
  assert.equal(ix.keys.length, 10);
  assert.ok(ix.keys[2].pubkey.equals(NITRO_MODE_B_ATTESTED_SIGNER_PLACEHOLDER));
  assert.equal(ix.keys[2].isWritable, false);
  assert.ok(ix.keys[7].pubkey.equals(SYSVAR_INSTRUCTIONS_PUBKEY) && !ix.keys[7].isWritable);
  const [usedNonce] = deriveUsedNoncePdaForSource(2, workload, commitment);
  assert.ok(ix.keys[3].pubkey.equals(usedNonce));
});

test("Mode B transaction places verify at index 0 and the consumer at index 1", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const nonce = new Uint8Array(32).fill(0x33);
  const actionHash = new Uint8Array(32).fill(0x22);
  const consumer = consumerIx(payer);
  const tx = buildVerifyNitroAttestationTxOversized(
    payer,
    workload,
    VERIFY_NITRO_MODE_B,
    10,
    actionHash,
    sampleDoc(32),
    nonce,
    payer.toBase58(),
    consumer,
  );
  assert.equal(tx.instructions.length, 2);
  assert.ok(tx.instructions[0].programId.equals(SOLANA_CONFIDENTIAL_COMPUTE_PROGRAM_ID));
  assert.equal(tx.instructions[0].data[8], VERIFY_NITRO_MODE_B);
  assert.ok(tx.instructions[1].programId.equals(consumer.programId));
});

test("Mode A transaction appends consumerIx when provided", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const consumer = consumerIx(payer);
  const tx = buildVerifyNitroAttestationTx(
    payer,
    workload,
    VERIFY_NITRO_MODE_A,
    1,
    new Uint8Array(32).fill(0x12),
    sampleDoc(8),
    new Uint8Array(32).fill(0x21),
    payer.toBase58(),
    consumer,
  );
  assert.equal(tx.instructions.length, 2);
  assert.equal(tx.instructions[0].data[8], VERIFY_NITRO_MODE_A);
  assert.ok(tx.instructions[1].programId.equals(consumer.programId));
  assert.deepEqual(Array.from(tx.instructions[1].data), [1, 2, 3]);
});

test("Mode A oversized transaction keeps consumerIx", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const consumer = consumerIx(payer);
  const tx = buildVerifyNitroAttestationTxOversized(
    payer,
    workload,
    VERIFY_NITRO_MODE_A,
    1,
    new Uint8Array(32).fill(0x12),
    sampleDoc(8),
    new Uint8Array(32).fill(0x21),
    payer.toBase58(),
    consumer,
  );
  assert.equal(tx.instructions.length, 2);
  assert.equal(tx.instructions[0].data[8], VERIFY_NITRO_MODE_A);
  assert.ok(tx.instructions[1].programId.equals(consumer.programId));
  assert.deepEqual(Array.from(tx.instructions[1].data), [1, 2, 3]);
});

test("Mode A transaction packs a single instruction", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const tx = buildVerifyNitroAttestationTxOversized(
    payer,
    workload,
    VERIFY_NITRO_MODE_A,
    0,
    new Uint8Array(32),
    sampleDoc(16),
    new Uint8Array(32).fill(1),
    payer.toBase58(),
  );
  assert.equal(tx.instructions.length, 1);
  assert.equal(tx.instructions[0].data[8], VERIFY_NITRO_MODE_A);
});

test("standard builders accept a small document that fits PACKET_DATA_SIZE", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const nonce = new Uint8Array(32).fill(0x21);
  const actionHash = new Uint8Array(32).fill(0x12);
  const document = sampleDoc(8);
  const ix = buildVerifyNitroAttestationIx(
    payer,
    workload,
    VERIFY_NITRO_MODE_A,
    1,
    actionHash,
    document,
    nonce,
  );
  assert.equal(ix.data.length, VERIFY_NITRO_ATTESTATION_HEADER_LEN + 8);

  const tx = buildVerifyNitroAttestationTx(
    payer,
    workload,
    VERIFY_NITRO_MODE_A,
    1,
    actionHash,
    document,
    nonce,
    payer.toBase58(),
  );
  assert.equal(tx.instructions.length, 1);
});

test("standard builders throw PacketTooLargeError for a max-size document", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const nonce = new Uint8Array(32).fill(0x21);
  const actionHash = new Uint8Array(32).fill(0x12);
  const document = sampleDoc(MAX_NITRO_DOCUMENT_LEN);

  try {
    buildVerifyNitroAttestationIx(
      payer,
      workload,
      VERIFY_NITRO_MODE_A,
      1,
      actionHash,
      document,
      nonce,
    );
    assert.fail("expected PacketTooLargeError");
  } catch (err) {
    assert.ok(err instanceof PacketTooLargeError);
    assert.ok(err.len > PACKET_DATA_SIZE);
  }

  const consumer = consumerIx(payer);
  try {
    buildVerifyNitroAttestationTx(
      payer,
      workload,
      VERIFY_NITRO_MODE_B,
      1,
      actionHash,
      document,
      nonce,
      payer.toBase58(),
      consumer,
    );
    assert.fail("expected PacketTooLargeError");
  } catch (err) {
    assert.ok(err instanceof PacketTooLargeError);
    assert.ok(err.len > PACKET_DATA_SIZE);
  }
});

test("empty and oversized documents fail before the packet check", () => {
  const payer = Keypair.generate().publicKey;
  const workload = Keypair.generate().publicKey;
  const nonce = new Uint8Array(32).fill(1);
  const actionHash = new Uint8Array(32).fill(2);
  assert.throws(
    () =>
      buildVerifyNitroAttestationIx(
        payer,
        workload,
        VERIFY_NITRO_MODE_A,
        1,
        actionHash,
        new Uint8Array(0),
        nonce,
      ),
    (err) => err instanceof Error && !(err instanceof PacketTooLargeError),
  );
  assert.throws(
    () =>
      buildVerifyNitroAttestationIxOversized(
        payer,
        workload,
        VERIFY_NITRO_MODE_A,
        1,
        actionHash,
        sampleDoc(MAX_NITRO_DOCUMENT_LEN + 1),
        nonce,
      ),
    new RegExp(`1 to ${MAX_NITRO_DOCUMENT_LEN}`),
  );
  assert.throws(
    () =>
      buildVerifyNitroAttestationIxOversized(
        payer,
        workload,
        2,
        1,
        actionHash,
        sampleDoc(8),
        nonce,
      ),
    /Nitro mode/,
  );
  assert.throws(
    () =>
      buildVerifyNitroAttestationTxOversized(
        payer,
        workload,
        VERIFY_NITRO_MODE_B,
        1,
        actionHash,
        sampleDoc(8),
        nonce,
        payer.toBase58(),
        null,
      ),
    /consumer instruction/,
  );
});
