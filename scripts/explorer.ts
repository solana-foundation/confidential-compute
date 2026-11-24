/**
 * Commonized Solana Explorer URL builder.
 * Supports Orb Markets (orbmarkets.io), Solana Explorer, and Solscan across clusters.
 */

export type Cluster = "mainnet-beta" | "devnet" | "testnet" | "localnet";
export type ExplorerProvider = "orb" | "solana" | "solscan";

export interface ExplorerOptions {
  provider?: ExplorerProvider;
  cluster?: Cluster;
}

const DEFAULT_PROVIDER: ExplorerProvider = "orb";
const DEFAULT_CLUSTER: Cluster = "devnet";

export class SolanaExplorer {
  readonly provider: ExplorerProvider;
  readonly cluster: Cluster;

  constructor(options: ExplorerOptions = {}) {
    this.provider = options.provider || DEFAULT_PROVIDER;
    this.cluster = options.cluster || DEFAULT_CLUSTER;
  }

  /**
   * Generates a transaction explorer URL.
   * Example: https://orbmarkets.io/tx/<sig>?cluster=devnet
   */
  tx(signature: string): string {
    const clusterParam = this.clusterParam();
    switch (this.provider) {
      case "orb":
        return `https://orbmarkets.io/tx/${signature}${clusterParam}`;
      case "solscan":
        const solscanCluster = this.cluster === "devnet" ? "?cluster=devnet" : "";
        return `https://solscan.io/tx/${signature}${solscanCluster}`;
      case "solana":
      default:
        return `https://explorer.solana.com/tx/${signature}${clusterParam}`;
    }
  }

  /**
   * Generates an account/address explorer URL.
   * Example: https://orbmarkets.io/address/<pubkey>?cluster=devnet
   */
  address(pubkey: string): string {
    const clusterParam = this.clusterParam();
    switch (this.provider) {
      case "orb":
        return `https://orbmarkets.io/address/${pubkey}${clusterParam}`;
      case "solscan":
        const solscanCluster = this.cluster === "devnet" ? "?cluster=devnet" : "";
        return `https://solscan.io/account/${pubkey}${solscanCluster}`;
      case "solana":
      default:
        return `https://explorer.solana.com/address/${pubkey}${clusterParam}`;
    }
  }

  private clusterParam(): string {
    if (this.cluster === "mainnet-beta") {
      return "";
    }
    return `?cluster=${this.cluster}`;
  }
}

export const defaultExplorer = new SolanaExplorer();
export const orbDevnet = new SolanaExplorer({ provider: "orb", cluster: "devnet" });
export const orbMainnet = new SolanaExplorer({ provider: "orb", cluster: "mainnet-beta" });
