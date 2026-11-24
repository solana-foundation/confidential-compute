#!/usr/bin/env bash
# Build solana-confidential-compute-verifier for SBPFv3 and assert ELF e_flags = 0x3 (SIMD-0500).
# Syscalls must be static Murmur3-32 hashes (SIMD-0178), not dynamic relocations.
# Linux and macOS. Homebrew binutils/llvm are keg-only, so PATH may omit readelf.
# @spec SCC-DEPLOY-001
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SO="${SBF_OUT_DIR:-${SBF_OUT_PATH:-$ROOT/target/deploy}}/solana_confidential_compute_verifier.so"
MANIFEST="$ROOT/programs/solana-confidential-compute-verifier/Cargo.toml"
# platform-tools < v1.53 emit a v3 header with v2 semantics; v1.56 is the Anza-recommended floor.
TOOLS_VERSION="${SOLANA_CC_SBF_TOOLS_VERSION:-v1.56}"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: scripts/build-sbpfv3.sh [mode] [cargo-build-sbf args...]

Modes:
  (default)           Compile programs/solana-confidential-compute-verifier --arch v3 and verify e_flags=0x3
                      and static Murmur3-32 syscalls (no SHT_DYNSYM / SHT_REL / SHT_RELA)
  --verify [PATH]     Verify an existing ELF (default: target/deploy/solana_confidential_compute_verifier.so)
  --self-test         Parser/readelf gate against synthetic ELF64 headers (no Solana toolchain)
  -h, --help          Show this help

Environment:
  SOLANA_CC_SBF_TOOLS_VERSION   platform-tools tag (default: v1.56)
  SBF_OUT_DIR / SBF_OUT_PATH
                             directory that contains solana_confidential_compute_verifier.so
EOF
}

require_python() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found (required to parse the ELF64 header)"
}

# Resolve cargo-build-sbf as an argv array (bash 3.2: no namerefs).
resolve_build_sbf() {
  if command -v cargo-build-sbf >/dev/null 2>&1; then
    BUILD_SBF=(cargo-build-sbf)
    return
  fi
  if cargo build-sbf --help >/dev/null 2>&1; then
    BUILD_SBF=(cargo build-sbf)
    return
  fi
  die "cargo-build-sbf not found. Install Solana CLI / cargo-build-sbf (>= v4.2.0 recommended)."
}

resolve_readelf() {
  local candidate
  local extras
  extras="/opt/homebrew/opt/binutils/bin/readelf
/usr/local/opt/binutils/bin/readelf
/opt/homebrew/opt/llvm/bin/llvm-readelf
/usr/local/opt/llvm/bin/llvm-readelf
${HOME}/.cache/solana/${TOOLS_VERSION}/platform-tools/llvm/bin/llvm-readelf"
  for candidate in readelf llvm-readelf greadelf $extras; do
    if [[ "$candidate" == /* ]]; then
      if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return
      fi
    elif command -v "$candidate" >/dev/null 2>&1; then
      echo "$candidate"
      return
    fi
  done
  echo ""
}

# Fail-closed ELF64 little-endian header parse. Source of truth on macOS
# when Homebrew readelf is keg-only and absent from PATH.
elf_flags_from_header() {
  local path="$1"
  require_python
  python3 - "$path" <<'PY'
import struct, sys

path = sys.argv[1]
with open(path, "rb") as fh:
    hdr = fh.read(64)

if len(hdr) < 64 or hdr[:4] != b"\x7fELF":
    sys.stderr.write("error: %s is not an ELF\n" % path)
    sys.exit(1)
if hdr[4] != 2:
    sys.stderr.write("error: %s is not ELF64\n" % path)
    sys.exit(1)
if hdr[5] != 1:
    sys.stderr.write("error: %s is not little-endian ELF\n" % path)
    sys.exit(1)

e_machine = struct.unpack_from("<H", hdr, 18)[0]
e_flags = struct.unpack_from("<I", hdr, 48)[0]
e_ehsize = struct.unpack_from("<H", hdr, 52)[0]
print("e_ehsize=%d e_machine=0x%x e_flags=0x%x" % (e_ehsize, e_machine, e_flags))

if e_ehsize != 64:
    sys.stderr.write("error: ELF header size %d != 64\n" % e_ehsize)
    sys.exit(1)
# EM_BPF (0xf7) is the SBPFv3 machine; EM_SBF (0x107) appears on older artifacts.
if e_machine not in (0xF7, 0x107):
    sys.stderr.write(
        "error: e_machine=0x%x (expected EM_BPF 0xf7 or EM_SBF 0x107)\n" % e_machine
    )
    sys.exit(1)
if e_flags != 3:
    sys.stderr.write("error: e_flags=0x%x (expected 0x3 for SBPFv3)\n" % e_flags)
    sys.exit(1)
PY
}

# SIMD-0178: syscall immediates are Murmur3-32 hashes. SBPFv3 omits the
# dynamic symbol table and load-time relocation sections.
# @spec SCC-DEPLOY-001
assert_static_murmur_syscalls() {
  local path="$1"
  require_python
  python3 - "$path" <<'PY'
import struct, sys

path = sys.argv[1]

def die(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(1)

def murmur3_32(data, seed=0):
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h = seed & 0xFFFFFFFF
    nblocks = len(data) // 4
    for i in range(nblocks):
        k = int.from_bytes(data[i * 4:(i + 1) * 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h

SYSCALL_NAMES = (
    "abort",
    "sol_panic_",
    "sol_log_",
    "sol_log_64_",
    "sol_log_compute_units_",
    "sol_log_pubkey",
    "sol_log_data",
    "sol_memcpy_",
    "sol_memmove_",
    "sol_memcmp_",
    "sol_memset_",
    "sol_alloc_free_",
    "sol_create_program_address",
    "sol_try_find_program_address",
    "sol_sha256",
    "sol_keccak256",
    "sol_blake3",
    "sol_secp256k1_recover",
    "sol_poseidon",
    "sol_invoke_signed_c",
    "sol_invoke_signed_rust",
    "sol_set_return_data",
    "sol_get_return_data",
    "sol_get_processed_sibling_instruction",
    "sol_get_stack_height",
    "sol_curve_validate_point",
    "sol_curve_group_op",
    "sol_curve_multiscalar_mul",
    "sol_curve_pairing_map",
    "sol_alt_bn128_group_op",
    "sol_alt_bn128_compression",
    "sol_big_mod_exp",
    "sol_remaining_compute_units",
    "sol_get_sysvar",
    "sol_get_epoch_stake",
    "sol_get_clock_sysvar",
    "sol_get_epoch_schedule_sysvar",
    "sol_get_rent_sysvar",
    "sol_get_fees_sysvar",
    "sol_get_epoch_rewards_sysvar",
    "sol_get_last_restart_slot",
)
KNOWN_HASHES = set(murmur3_32(name.encode("ascii")) for name in SYSCALL_NAMES)
# SIMD-0178 example: murmur32("abort") immediate is 11 1a fc b6.
if murmur3_32(b"abort") != 0xB6FC1A11:
    die("murmur3_32(\"abort\") != 0xb6fc1a11")

SHT_PROGBITS = 1
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_REL = 9
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4
PT_DYNAMIC = 2
DYNAMIC_NAMES = {".dynsym", ".dynamic", ".rel.dyn", ".rela.dyn", ".rel.plt", ".rela.plt"}
DYNAMIC_TYPES = {SHT_RELA, SHT_DYNAMIC, SHT_REL, SHT_DYNSYM}

with open(path, "rb") as fh:
    elf = fh.read()
if len(elf) < 64:
    die("%s is shorter than an ELF header" % path)

e_phoff = struct.unpack_from("<Q", elf, 32)[0]
e_shoff = struct.unpack_from("<Q", elf, 40)[0]
e_phentsize = struct.unpack_from("<H", elf, 54)[0]
e_phnum = struct.unpack_from("<H", elf, 56)[0]
e_shentsize = struct.unpack_from("<H", elf, 58)[0]
e_shnum = struct.unpack_from("<H", elf, 60)[0]
e_shstrndx = struct.unpack_from("<H", elf, 62)[0]

if e_phnum:
    if e_phentsize != 56:
        die("e_phentsize %d != 56" % e_phentsize)
    for i in range(e_phnum):
        off = e_phoff + i * 56
        if off + 56 > len(elf):
            die("program header %d is truncated" % i)
        p_type = struct.unpack_from("<I", elf, off)[0]
        if p_type == PT_DYNAMIC:
            die("PT_DYNAMIC is present; SBPFv3 syscalls must not use dynamic relocations")

exec_blobs = []
if e_shnum:
    if e_shentsize != 64:
        die("e_shentsize %d != 64" % e_shentsize)
    if e_shoff + e_shnum * 64 > len(elf):
        die("section header table is truncated")
    strtab = b""
    if e_shstrndx < e_shnum:
        str_hdr = e_shoff + e_shstrndx * 64
        str_off = struct.unpack_from("<Q", elf, str_hdr + 24)[0]
        str_size = struct.unpack_from("<Q", elf, str_hdr + 32)[0]
        if str_off + str_size > len(elf):
            die("section name table is truncated")
        strtab = elf[str_off:str_off + str_size]
    for i in range(e_shnum):
        off = e_shoff + i * 64
        sh_name = struct.unpack_from("<I", elf, off)[0]
        sh_type = struct.unpack_from("<I", elf, off + 4)[0]
        sh_flags = struct.unpack_from("<Q", elf, off + 8)[0]
        sh_offset = struct.unpack_from("<Q", elf, off + 24)[0]
        sh_size = struct.unpack_from("<Q", elf, off + 32)[0]
        name = ""
        if strtab and sh_name < len(strtab):
            end = strtab.find(b"\x00", sh_name)
            if end < 0:
                end = len(strtab)
            name = strtab[sh_name:end].decode("ascii", "replace")
        if sh_type in DYNAMIC_TYPES or name in DYNAMIC_NAMES:
            die(
                "dynamic relocation section %s type %d; SBPFv3 requires static Murmur3-32 syscalls"
                % (name or ("#%d" % i), sh_type)
            )
        if sh_type == SHT_PROGBITS and (sh_flags & SHF_EXECINSTR) and sh_size:
            if sh_offset + sh_size > len(elf):
                die("executable section %s is truncated" % (name or ("#%d" % i)))
            exec_blobs.append(elf[sh_offset:sh_offset + sh_size])

if not exec_blobs:
    die("ELF has no executable section; header-only fixtures are not artifacts")

saw = False
for blob in exec_blobs:
    if len(blob) % 8 != 0:
        die("executable section length %d is not a multiple of 8" % len(blob))
    for i in range(0, len(blob), 8):
        insn = blob[i:i + 8]
        if insn[0] != 0x85 or (insn[1] >> 4) != 0:
            continue
        imm = int.from_bytes(insn[4:8], "little")
        if imm == 0xFFFFFFFF:
            die("unresolved call -1 at executable offset %d (dynamic symbol relocation)" % i)
        if imm not in KNOWN_HASHES:
            die("call immediate 0x%08x is not a Murmur3-32 syscall hash" % imm)
        saw = True
if not saw:
    die("executable ELF has no static Murmur3-32 syscall")
print("static syscalls: ok (Murmur3-32, no dynamic symbol relocations)")
PY
}

# GNU readelf / llvm-readelf / greadelf. Anza prints:
#   Flags:                             0x3, CPU Version: 3
assert_readelf_flags() {
  local path="$1"
  local tool="$2"
  local output
  output="$("$tool" -h "$path")"
  printf '%s\n' "$output"

  if printf '%s\n' "$output" | grep -E -q 'Flags:[[:space:]]*0x0*3([^0-9a-fA-F]|$)'; then
    return 0
  fi
  if printf '%s\n' "$output" | grep -E -qi 'CPU Version:[[:space:]]*3([^0-9]|$)'; then
    return 0
  fi
  echo "error: SBPFv3 e_flags check failed (expected Flags: 0x3 from $tool)" >&2
  return 1
}

verify_elf() {
  local path="$1"
  [[ -f "$path" ]] || die "missing $path"
  echo "==> ELF header ($path)"
  local readelf
  readelf="$(resolve_readelf)"
  if [[ -n "$readelf" ]]; then
    echo "    readelf: $readelf"
    assert_readelf_flags "$path" "$readelf" || return $?
  else
    echo "readelf not found; parsing ELF64 header at offset 48"
  fi
  elf_flags_from_header "$path"
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    return $rc
  fi
  assert_static_murmur_syscalls "$path" || return $?
  local size
  size="$(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' "$path")"
  echo "==> ok: $path ($size bytes) e_flags=0x3"
}

run_self_test() {
  require_python
  local workdir
  workdir="$(mktemp -d "${TMPDIR:-/tmp}/solana-cc-sbpfv3.XXXXXX")"
  trap "rm -rf '$workdir'" EXIT RETURN

  python3 - "$workdir" <<'PY'
import os, struct, subprocess, sys

workdir = sys.argv[1]
script = os.path.abspath(sys.argv[0]) if False else None


def write_elf(path, flags=3, klass=2, data=1, machine=0xF7, ehsize=64, magic=b"\x7fELF"):
    hdr = bytearray(64)
    hdr[0:4] = magic
    hdr[4] = klass
    hdr[5] = data
    hdr[6] = 1  # EI_VERSION
    struct.pack_into("<H", hdr, 16, 3)  # ET_DYN
    struct.pack_into("<H", hdr, 18, machine)
    struct.pack_into("<I", hdr, 20, 1)
    struct.pack_into("<Q", hdr, 32, 0)  # e_phoff = 0 (no program headers)
    struct.pack_into("<I", hdr, 48, flags)
    struct.pack_into("<H", hdr, 52, ehsize)
    with open(path, "wb") as fh:
        fh.write(hdr)


def expect(path, ok):
    env = os.environ.copy()
    cmd = ["bash", os.path.join(os.path.dirname(os.path.dirname(workdir)), "never")]
    # Invoked from the shell wrapper below; this block only writes fixtures.
    _ = (path, ok, env, cmd)


write_elf(os.path.join(workdir, "good.so"), flags=3)
write_elf(os.path.join(workdir, "v2.so"), flags=2)
write_elf(os.path.join(workdir, "be.so"), flags=3, data=2)
write_elf(os.path.join(workdir, "machine.so"), flags=3, machine=0x3E)
with open(os.path.join(workdir, "not-elf.so"), "wb") as fh:
    fh.write(b"not an elf" + b"\x00" * 54)
print("fixtures=%s" % workdir)
PY

  echo "==> self-test fixtures in $workdir"

  if verify_elf "$workdir/good.so" >/dev/null 2>&1; then
    die "self-test: header-only ELF must be rejected"
  fi
  echo "    reject header-only ELF: ok"

  if verify_elf "$workdir/v2.so" >/dev/null 2>&1; then
    die "self-test: v2 ELF (e_flags=0x2) must be rejected"
  fi
  echo "    reject e_flags=0x2: ok"

  if verify_elf "$workdir/be.so" >/dev/null 2>&1; then
    die "self-test: big-endian ELF must be rejected"
  fi
  echo "    reject big-endian: ok"

  if verify_elf "$workdir/machine.so" >/dev/null 2>&1; then
    die "self-test: non-BPF e_machine must be rejected"
  fi
  echo "    reject e_machine: ok"

  if verify_elf "$workdir/not-elf.so" >/dev/null 2>&1; then
    die "self-test: non-ELF must be rejected"
  fi
  echo "    reject non-ELF: ok"

  python3 - "$workdir" <<'PY'
import os, struct, sys

workdir = sys.argv[1]
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNSYM = 11
SHF_ALLOC = 2
SHF_EXECINSTR = 4
ABORT = bytes.fromhex("85000000111afcb6")
INTERNAL = bytes.fromhex("8510000001000000")
UNRESOLVED = bytes.fromhex("85000000ffffffff")


def pack_elf(path, text, extras):
    sections = [(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, text)] + list(extras)
    shstr = bytearray(b"\x00")
    name_off = {}
    for name, _typ, _flags, _content in sections:
        name_off[name] = len(shstr)
        shstr += name.encode("ascii") + b"\x00"
    name_off[".shstrtab"] = len(shstr)
    shstr += b".shstrtab\x00"

    body = bytearray()
    offsets = []
    for _name, _typ, _flags, content in sections:
        while len(body) % 8:
            body.append(0)
        offsets.append(64 + len(body))
        body += content
    while len(body) % 8:
        body.append(0)
    shstr_off = 64 + len(body)
    body += shstr
    shnum = 1 + len(sections) + 1
    shoff = 64 + len(body)

    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    hdr[6] = 1
    struct.pack_into("<H", hdr, 16, 3)
    struct.pack_into("<H", hdr, 18, 0xF7)
    struct.pack_into("<I", hdr, 20, 1)
    struct.pack_into("<Q", hdr, 40, shoff)
    struct.pack_into("<I", hdr, 48, 3)
    struct.pack_into("<H", hdr, 52, 64)
    struct.pack_into("<H", hdr, 58, 64)
    struct.pack_into("<H", hdr, 60, shnum)
    struct.pack_into("<H", hdr, 62, shnum - 1)

    shdrs = bytearray(shnum * 64)
    for i, (name, typ, flags, content) in enumerate(sections, start=1):
        off = i * 64
        struct.pack_into("<I", shdrs, off, name_off[name])
        struct.pack_into("<I", shdrs, off + 4, typ)
        struct.pack_into("<Q", shdrs, off + 8, flags)
        struct.pack_into("<Q", shdrs, off + 24, offsets[i - 1])
        struct.pack_into("<Q", shdrs, off + 32, len(content))
    off = (shnum - 1) * 64
    struct.pack_into("<I", shdrs, off, name_off[".shstrtab"])
    struct.pack_into("<I", shdrs, off + 4, SHT_STRTAB)
    struct.pack_into("<Q", shdrs, off + 24, shstr_off)
    struct.pack_into("<Q", shdrs, off + 32, len(shstr))
    with open(path, "wb") as fh:
        fh.write(hdr)
        fh.write(body)
        fh.write(shdrs)


def pack_pt_dynamic(path):
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4] = 2
    hdr[5] = 1
    hdr[6] = 1
    struct.pack_into("<H", hdr, 16, 3)
    struct.pack_into("<H", hdr, 18, 0xF7)
    struct.pack_into("<I", hdr, 20, 1)
    struct.pack_into("<Q", hdr, 32, 64)  # e_phoff
    struct.pack_into("<I", hdr, 48, 3)
    struct.pack_into("<H", hdr, 52, 64)
    struct.pack_into("<H", hdr, 54, 56)  # e_phentsize
    struct.pack_into("<H", hdr, 56, 1)  # e_phnum
    phdr = bytearray(56)
    struct.pack_into("<I", phdr, 0, 2)  # PT_DYNAMIC
    with open(path, "wb") as fh:
        fh.write(hdr)
        fh.write(phdr)


pack_elf(os.path.join(workdir, "static-syscall.so"), INTERNAL + ABORT, [])
pack_elf(os.path.join(workdir, "unresolved-call.so"), ABORT + UNRESOLVED, [])
pack_elf(
    os.path.join(workdir, "dynsym.so"),
    ABORT,
    [(".dynsym", SHT_DYNSYM, SHF_ALLOC, b"\x00" * 24)],
)
pack_elf(
    os.path.join(workdir, "rela.so"),
    ABORT,
    [(".rela.dyn", SHT_RELA, SHF_ALLOC, b"\x00" * 24)],
)
pack_pt_dynamic(os.path.join(workdir, "pt-dynamic.so"))
print("syscall-fixtures=%s" % workdir)
PY

  verify_elf "$workdir/static-syscall.so"
  echo "    static murmur3 syscall: ok"

  if verify_elf "$workdir/unresolved-call.so" >/dev/null 2>&1; then
    die "self-test: unresolved call -1 must be rejected"
  fi
  echo "    reject call -1: ok"

  if verify_elf "$workdir/dynsym.so" >/dev/null 2>&1; then
    die "self-test: SHT_DYNSYM must be rejected"
  fi
  echo "    reject SHT_DYNSYM: ok"

  if verify_elf "$workdir/rela.so" >/dev/null 2>&1; then
    die "self-test: SHT_RELA must be rejected"
  fi
  echo "    reject SHT_RELA: ok"

  if verify_elf "$workdir/pt-dynamic.so" >/dev/null 2>&1; then
    die "self-test: PT_DYNAMIC must be rejected"
  fi
  echo "    reject PT_DYNAMIC: ok"

  # Exercise build-mode status/diagnostic handling without installing a toolchain.
  mkdir -p "$workdir/bin" "$workdir/out"
  cat > "$workdir/bin/cargo-build-sbf" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
# The build driver must preserve the separator before cargo-only arguments.
if [[ "${SOLANA_CC_TEST_BUILD_MODE:-}" == args ]]; then
  [[ "${*: -3}" == "-- --locked -j4" ]] || exit 43
fi
if [[ "${SOLANA_CC_TEST_BUILD_MODE:-}" == fail ]]; then exit 42; fi
cp "$SOLANA_CC_TEST_ELF" "$SBF_OUT_DIR/solana_confidential_compute_verifier.so"
if [[ "${SOLANA_CC_TEST_BUILD_MODE:-}" == stack ]]; then
  echo 'Error: Stack offset of 5000 exceeded max offset of 4096' >&2
elif [[ "${SOLANA_CC_TEST_BUILD_MODE:-}" == frame ]]; then
  echo 'Error: Function rsa_public_exp overflows the maximum allowed frame space by accessing an offset 26112 bytes greater than the maximum of 4096. Estimated function frame size: 30208 bytes.' >&2
fi
SH
  chmod +x "$workdir/bin/cargo-build-sbf"
  PATH="$workdir/bin:$PATH" SBF_OUT_DIR="$workdir/out" \
    SOLANA_CC_TEST_ELF="$workdir/static-syscall.so" SOLANA_CC_TEST_BUILD_MODE=args \
    bash "$ROOT/scripts/build-sbpfv3.sh" -- --locked -j4
  if PATH="$workdir/bin:$PATH" SBF_OUT_DIR="$workdir/out" \
    SOLANA_CC_TEST_ELF="$workdir/static-syscall.so" SOLANA_CC_TEST_BUILD_MODE=stack \
    bash "$ROOT/scripts/build-sbpfv3.sh" >/dev/null 2>&1; then
    die "self-test: successful compiler exit with stack overflow diagnostic must fail"
  fi
  echo "    reject stack overflow diagnostic: ok"
  if PATH="$workdir/bin:$PATH" SBF_OUT_DIR="$workdir/out" \
    SOLANA_CC_TEST_ELF="$workdir/static-syscall.so" SOLANA_CC_TEST_BUILD_MODE=frame \
    bash "$ROOT/scripts/build-sbpfv3.sh" >/dev/null 2>&1; then
    die "self-test: LLVM frame-space overflow diagnostic must fail"
  fi
  echo "    reject LLVM frame-space overflow diagnostic: ok"
  if PATH="$workdir/bin:$PATH" SBF_OUT_DIR="$workdir/out" \
    SOLANA_CC_TEST_ELF="$workdir/static-syscall.so" SOLANA_CC_TEST_BUILD_MODE=fail \
    bash "$ROOT/scripts/build-sbpfv3.sh" >/dev/null 2>&1; then
    die "self-test: compiler failure must fail even with a stale artifact"
  fi
  echo "    reject compiler failure/stale artifact: ok"
  echo "==> self-test ok (synthetic parser and build-driver controls; no real SBF proof)"
}

MODE="build"
VERIFY_PATH=""
PASS_THROUGH=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --self-test)
      MODE="self-test"
      shift
      ;;
    --verify)
      MODE="verify"
      if [[ $# -ge 2 && "$2" != --* ]]; then
        VERIFY_PATH="$2"
        shift 2
      else
        shift
      fi
      ;;
    --verify=*)
      MODE="verify"
      VERIFY_PATH="${1#*=}"
      shift
      ;;
    --)
      # Preserve cargo-build-sbf's separator for cargo-only flags such as --locked.
      PASS_THROUGH+=("--")
      shift
      while [[ $# -gt 0 ]]; do
        PASS_THROUGH+=("$1")
        shift
      done
      break
      ;;
    *)
      PASS_THROUGH+=("$1")
      shift
      ;;
  esac
done

case "$MODE" in
  self-test)
    run_self_test
    exit 0
    ;;
  verify)
    if [[ -z "$VERIFY_PATH" ]]; then
      VERIFY_PATH="$SO"
    fi
    verify_elf "$VERIFY_PATH"
    exit 0
    ;;
  build)
    resolve_build_sbf
    echo "==> SBPFv3 build (SCC-DEPLOY-001)"
    echo "    toolchain: ${BUILD_SBF[*]}"
    echo "    arch:      v3"
    echo "    tools:     $TOOLS_VERSION"
    echo "    manifest:  $MANIFEST"
    # Remove only the selected output so an old ELF cannot satisfy this build.
    rm -f -- "$SO"
    build_log="$(mktemp "${TMPDIR:-/tmp}/solana-cc-sbf-build.XXXXXX")"
    trap 'rm -f -- "$build_log"' EXIT
    "${BUILD_SBF[@]}" --arch v3 --tools-version "$TOOLS_VERSION" --manifest-path "$MANIFEST" \
      --sbf-out-dir "$(dirname "$SO")" \
      "${PASS_THROUGH[@]+"${PASS_THROUGH[@]}"}" 2>&1 | tee "$build_log"
    # LLVM can print stack violations while cargo-build-sbf still exits zero.
    if grep -Eiq 'stack offset.*exceeded|stack frame.*(exceed|too large)|overflows the maximum allowed frame space' "$build_log"; then
      die "SBF stack limit diagnostic; refusing artifact"
    fi
    verify_elf "$SO"
    ;;
  *)
    die "unknown mode $MODE"
    ;;
esac
