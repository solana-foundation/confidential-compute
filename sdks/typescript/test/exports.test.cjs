const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createRequire } = require("node:module");
test("supported package root loads; internal subpaths are blocked", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "solana-cc-exports-"));
  try {
    fs.mkdirSync(path.join(dir, "node_modules/@solana"), {recursive: true});
    fs.symlinkSync(path.resolve(__dirname, ".."), path.join(dir, "node_modules/@solana/confidential-compute"));
    const consumer = createRequire(path.join(dir, "consumer.cjs"));
    assert.equal(typeof consumer("@solana/confidential-compute").buildRegisterSignerIx, "function");
    for (const subpath of ["dist/internal/oversized.js", "internal/oversized", "src/internal/oversized"]) {
      assert.throws(() => consumer(`@solana/confidential-compute/${subpath}`), {code: "ERR_PACKAGE_PATH_NOT_EXPORTED"});
    }
  } finally { fs.rmSync(dir, {recursive: true, force: true}); }
});
