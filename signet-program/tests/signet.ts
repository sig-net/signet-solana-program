import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Signet } from "../target/types/signet";
import BN from "bn.js";

describe("signet-program", async () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.signet as Program<Signet>;

  const deposit = new BN(0);
  const tx = await program.methods.initialize(deposit).rpc();
  console.log("Transaction signature for initialize:", tx);
});

it("Signs a payload", async () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.signet as Program<Signet>;

  const payload = Array.from(new Uint8Array(32).fill(1));
  const keyVersion = 0;
  const path = "path";
  const algo = "";
  const dest = "";
  const params = "";

  const tx = await program.methods
    .sign(payload, keyVersion, path, algo, dest, params)
    .rpc();

  console.log("Transaction signature for sign:", tx);
});
