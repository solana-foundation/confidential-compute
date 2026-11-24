import { describe, expect, test } from "bun:test";
import { SolanaExplorer, orbDevnet, orbMainnet } from "./explorer";

describe("SolanaExplorer URL Generator", () => {
  const sampleTx = "5GLHEiHYiQ9EsQPApUpJU4S5zNwgE7ykroViH8FR9viJj4342vh9WKxbR97PcuawQZuYF4NwtvBGYtqTMZBzpvLW";
  const sampleAddress = "BNiGJpc6zkmkk7Jir1ggRfyxFy2fwjMmt2BUDUEg4eCG";

  test("generates Orb Markets Devnet transaction URLs", () => {
    const url = orbDevnet.tx(sampleTx);
    expect(url).toBe(
      `https://orbmarkets.io/tx/${sampleTx}?cluster=devnet`
    );
  });

  test("generates Orb Markets Devnet address URLs", () => {
    const url = orbDevnet.address(sampleAddress);
    expect(url).toBe(
      `https://orbmarkets.io/address/${sampleAddress}?cluster=devnet`
    );
  });

  test("generates Orb Markets Mainnet transaction URLs without cluster param", () => {
    const url = orbMainnet.tx(sampleTx);
    expect(url).toBe(
      `https://orbmarkets.io/tx/${sampleTx}`
    );
  });

  test("generates Orb Markets Mainnet address URLs without cluster param", () => {
    const url = orbMainnet.address(sampleAddress);
    expect(url).toBe(
      `https://orbmarkets.io/address/${sampleAddress}`
    );
  });

  test("supports custom cluster option", () => {
    const custom = new SolanaExplorer({ provider: "orb", cluster: "testnet" });
    expect(custom.tx(sampleTx)).toBe(
      `https://orbmarkets.io/tx/${sampleTx}?cluster=testnet`
    );
  });

  test("supports fallback to Solana Explorer", () => {
    const solExplorer = new SolanaExplorer({ provider: "solana", cluster: "devnet" });
    expect(solExplorer.tx(sampleTx)).toBe(
      `https://explorer.solana.com/tx/${sampleTx}?cluster=devnet`
    );
  });
});
