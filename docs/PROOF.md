# mirror-pool - proof of operation

This file has two independent, honestly-labeled proofs of the same program:
a **public Solana devnet deployment** (top, browser-verifiable on the Solana
Explorer) and the original **local Surfpool mainnet-mirror run** (bottom).

> **The tables below were captured against the bytecode that is deployed at that
> address right now.** The devnet program was upgraded in place to the current
> build (signature
> `27Hg4jV8W4UeCY9RX9kpNfwJoMVz5BE4qRMpV9AqwN1Z3Y1bygy9vMwszM4E4vhZs69otSHg3Dwrn61DDTGfVLbF`,
> slot `479622920`; the dumped on-chain bytes are byte-for-byte the locally built
> `mirror_pool.so`, sha256
> `5b8cfdc0112b084ce3a5189333b719388a8b29a3f6300a7fed531ba4c3fa7d93`), and BOTH
> devnet suites were then re-run against it. That is the point of the re-run: the
> program a reviewer inspects on the Explorer is the program these numbers
> describe. The earlier tables, captured against older bytecode at the same
> address, are gone rather than annotated.
>
> This build carries three things the pre-registry one did not: the write-once
> digest-pinned verifying-key registry with its `InitVk` instruction
> ([`VK_REGISTRY.md`](VK_REGISTRY.md)), the ZK-escrow domain-separation fix, and
> phase-2 **ceremony** keys for ALL THREE circuits. Assertion counts moved with
> it: behavioral 17 -> 18 and confidential 25 -> 27, the extra rows being the
> verifying-key publication and, on the confidential side, the lookup table that
> keeps a `Transact` inside one packet now that it carries the registry account.

> **The funding-round soak below ran on a local Surfpool, not on devnet.** It was
> re-run against the SAME bytecode (a fresh deployment of the identical
> `mirror_pool.so`) and passed 27/27, so it describes today's program, but its
> signatures are local-validator signatures and resolve on no public explorer.
> That is a deliberate scope choice, not an unverified claim: the funding soak
> drives four participants through shield, unshield, batched release and a
> mid-round failure, and paying for that on a public cluster buys nothing the
> local run does not already establish.

> **The ZK escrow fix, for the record.** The crowd `Commit` leaf is
> domain-separated from the ZK deposit leaf by the program
> (`crowd_leaf = Poseidon(CROWD_LEAF_DOMAIN, commitment)`), and a pool fixes one
> `zk_denomination` at init that `CommitDeposit`, `SettleZk` and
> `SettleZkAssociated` all require. Together they close a fund-theft hole in which
> a fee-only crowd commit could spend a depositor's escrow
> ([`THREAT_MODEL.md`](THREAT_MODEL.md) section 4). The runs below exercise the
> bytecode that has both; the inverted attack test
> `settle_zk_rejects_a_fee_only_crowd_leaf_spending_a_depositors_escrow` in the
> mollusk suite is what proves the hole is closed rather than merely unexercised.

> **Proving is in-process pure Rust.** The participant CLI proves with
> `ark-circom`/`ark-groth16` and spawns no Node process; `--use-snarkjs` is a
> legacy fallback. `circom`/`snarkjs` are still needed at BUILD time to produce
> the `.wasm`/`.r1cs`/`.zkey` artifacts, and `snarkjs groth16 setup` is still the
> ceremony's phase-2 starting point. Because all three deployed verifying keys are
> ceremony outputs, the CLI proves under a ceremony `.mpk` (`--proving-key`), not
> under the dev `.zkey`; it refuses to emit a proof that does not verify against
> the committed key, so a key mismatch is a local error rather than a wasted fee.

**What the ZK step in these runs does and does not show.** Each behavioral soak
makes exactly ONE ZK deposit, into a freshly opened window, so the window it
settles holds a single deposit. Those assertions therefore prove the mechanism -
the proof verifies on-chain, the `actionHash` binding holds, the nullifier
prevents replay, the escrow moves - and prove **nothing about anonymity**: a set
of one is not an anonymity set. `SettleZk` has no on-chain k-floor and would
settle that window regardless; why that is deliberate, and where the floor is
enforced instead, is in [`THREAT_MODEL.md`](THREAT_MODEL.md) section 4. The
crowd-path assertions are the ones that exercise a floor (`k_floor = 3`,
including the under-floor epoch that correctly does not settle).

---

# Public devnet deployment (browser-verifiable)

Both soak suites were run against **public Solana devnet**
(`https://api.devnet.solana.com`) - a real, shared, public cluster. Every
signature below is a real devnet transaction that resolves on the Solana
Explorer; anyone can click through and verify it. This is **devnet, not
mainnet-beta**: it proves the program deploys and every flow executes on a
live public cluster, exactly as it would on mainnet, without spending
mainnet SOL.

- program id: `EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq`
- program (Explorer): https://explorer.solana.com/address/EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq?cluster=devnet
- deploy/upgrade transaction: https://explorer.solana.com/tx/27Hg4jV8W4UeCY9RX9kpNfwJoMVz5BE4qRMpV9AqwN1Z3Y1bygy9vMwszM4E4vhZs69otSHg3Dwrn61DDTGfVLbF?cluster=devnet
- cluster: devnet (`https://api.devnet.solana.com`)
- driving commitment: `confirmed` for submission; every captured signature
  below was then re-confirmed at the `finalized` commitment before listing.

The program id above is a fresh, bounty-dedicated keypair (kept gitignored
under `.soak/keys/`). It was deployed and has since been upgraded in place, so
the id and every Explorer link in this document survive; the SHA-256 of the
on-chain program bytes equals the SHA-256 of the locally built `mirror_pool.so`
(`5b8cfdc0112b084ce3a5189333b719388a8b29a3f6300a7fed531ba4c3fa7d93`), so the
deployed program is exactly the source in this repo. Both suites below were run
against that bytecode, after the upgrade.

The three verifying-key registries are published and readable on chain:

| circuit | registry PDA | `InitVk` transaction | sha256(vk) |
| --- | --- | --- | --- |
| membership | `6fkK14YXovKkJQ7z2Df7sBeCGPEnRK2XGBrRkMJJbRYg` | [`8VgiyRtg...`](https://explorer.solana.com/tx/8VgiyRtg1qb5g9U3kJNWturZ3tx7XjKbKUUJXtnCSnRPQAPRS7JyynR9du1YsKEDkKBxQv9umVvZ2gHmZSDVV2Q?cluster=devnet) | `be5f776d2a4ba83655c50a9ecf47192cd3aa74075cd9e3d8a62bd99e043e4c76` |
| transaction | `BD1cm4jqbDHxgWX7ZfLmFaWWc1wSJFr5h68YesrkuCfW` | [`61ysGZNm...`](https://explorer.solana.com/tx/61ysGZNmMYNwNgZSsLGTJuargPezabCYnpAKjU33BhXkcVYWedUkow8GF2b9gQ4eMpa3SJeJLPFzgqRrgNjYbWWe?cluster=devnet) | `4b542099cea5bd4dfdfd6f9d5d649bc23acd9aab35d8f3ac1a984e13b38e28c1` |
| association | `3EyfUQZFSEz1VcTkCK3EsUV5uE8XqyCBmCQHETqjhWVn` | [`5BxnXZM3...`](https://explorer.solana.com/tx/5BxnXZM37b92vazgeGs7XUX7fdHd54rNBSsojLGYmvEGttepxCj5fLLFRJj3cBggSqfzJAYWUsJ7FMiCRBzkJFop?cluster=devnet) | `90d13582aba26708672b3f118dea345c9636534b1b9de3fd7fce4708062832ee` |

Each of those three digests is a phase-2 CEREMONY key, and each is the only key
its registry can ever hold: `InitVk` hashes the bytes and refuses anything but
the digest the bytecode pins, and there is no update instruction.

## Behavioral soak - crowd + ZK settlement (devnet)

Fresh pool per run (fresh relay authority). Config: epoch_slots=128, k_floor=3, entry_fee=1000000 lamports, reward_bps=2500.

- pool PDA: `3Cj2JhrT7WQsjew5a6EFhHMWLpmamNKNBrRoYmnCHCVw` (authority / relay `3AQ4kzbDe8fmAXYVX9fqEfoXD3hCUb86f4drh6byMpf2`)
- pool (Explorer): https://explorer.solana.com/address/3Cj2JhrT7WQsjew5a6EFhHMWLpmamNKNBrRoYmnCHCVw?cluster=devnet
- ZK opt-in escrow amount: 50000000 lamports
- reward pool accrued at end of run: 1750000 lamports
- total leaves appended: 7

What was exercised: the membership verifying key is published into its
write-once registry; 4 participants commit the SAME PlainTransfer action into
one shared epoch, settled by ONE atomic gasless transaction (ComputeBudget +
SettleEpoch + 4 identical transfers, over a pool ALT); a ZK opt-in escrow is
settled by a Groth16 SettleZk to a fresh recipient, proved in-process under the
phase-2 CEREMONY proving key; and the adversarial cases (under-floor no-settle,
duplicate nullifier, re-settle, mismatched-recipient, replay) all fail closed
on-chain.

### On-chain assertions (18/18)

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq |
| PASS | membership verifying key published into its write-once registry PDA | init_vk: already published (registry holds exactly the committed key) |
| PASS | pool initialized with fixed config | version=1 epoch_slots=128 k_floor=3 entry_fee=1000000 authority=relay |
| PASS | pool ALT created + extended | alt=31VjbncRjkHdZAh3Sr6VpQZAbRhgczM6s6dMWrXbE6Z7 (6 shared accounts) |
| PASS | 4 commits batched into one shared epoch | epoch_id=3747071 commit_count=4 settled=false |
| PASS | duplicate crowd nullifier rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x3; 5 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program 1 |
| PASS | crowd epoch marked settled on-chain | epoch_id=3747071 settled=true |
| PASS | 4 nullifier PDAs created (anti-replay) | 4/4 nullifier PDAs exist and are program-owned |
| PASS | 4 identical transfers executed atomically | sink credited 40000000 lamports (= 4 x 10000000 bucket) |
| PASS | re-settle of a settled epoch rejected (EpochAlreadySettled) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x6; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |
| PASS | under-floor epoch rejected on-chain (BelowKFloor) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x2; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |
| PASS | under-floor epoch rolled forward off-chain (coordinator) | coordinator.on_slot returned RolledForward (real_k < k_floor) |
| PASS | Groth16 membership proof generated + verified (in-process ark-groth16) | mirror-cli prove produced a SettleZk whose proof it generated and verified in-process |
| PASS | SettleZk authority == pool relay | authority=3AQ4kzbDe8fmAXYVX9fqEfoXD3hCUb86f4drh6byMpf2 |
| PASS | ZK settle to mismatched recipient rejected (ActionHashMismatch) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0xe; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |
| PASS | escrow landed at the FRESH recipient | recipient credited 50000000 lamports (= escrow 50000000) |
| PASS | ZK nullifier PDA created (anti-replay) | nullifier PDA 7NvAhLUrxFi1qrFWv2by4tpizwCN19A89hA4yT8hKeUF exists + program-owned |
| PASS | ZK replay rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x3; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |

The `init_vk` row reports "already published" because the registry is per
PROGRAM, not per pool, and this program id had already had its membership key
published by an earlier run of this same suite. `init-vk` re-reads the account
and confirms it holds exactly the committed key, so the assertion is a check on
the key in force rather than on whether this particular run wrote it. The
transaction that did write it is the first row of the signature table.

### Finalized transaction signatures + compute units

| flow | signature (Explorer) | commitment | CU consumed |
| --- | --- | --- | --- |
| init_vk_membership | [`8VgiyRtg1qb5g9U3kJNWturZ3tx7XjKbKUUJXtnCSnRPQAPRS7JyynR9du1YsKEDkKBxQv9umVvZ2gHmZSDVV2Q`](https://explorer.solana.com/tx/8VgiyRtg1qb5g9U3kJNWturZ3tx7XjKbKUUJXtnCSnRPQAPRS7JyynR9du1YsKEDkKBxQv9umVvZ2gHmZSDVV2Q?cluster=devnet) | Finalized | 5472 |
| init_pool | [`5AJU1aMvzr51UA2StiXkwSFBiw54g9n8aUV3DpWKWFWUNYReuP9nHBeMX47AFF68Y9SxtbAqVTaZAwx1822aFgE2`](https://explorer.solana.com/tx/5AJU1aMvzr51UA2StiXkwSFBiw54g9n8aUV3DpWKWFWUNYReuP9nHBeMX47AFF68Y9SxtbAqVTaZAwx1822aFgE2?cluster=devnet) | Finalized | 20461 |
| crowd_commit_0 | [`5fhA9a2p3Y2q4uKN2CQri1zRdwB6HNed9iM12XXMG2Y8AwtjJjwFqbb7E17oTQg7LWnEjRH63CYjCtnfCzMNZ45g`](https://explorer.solana.com/tx/5fhA9a2p3Y2q4uKN2CQri1zRdwB6HNed9iM12XXMG2Y8AwtjJjwFqbb7E17oTQg7LWnEjRH63CYjCtnfCzMNZ45g?cluster=devnet) | Finalized | 40331 |
| crowd_commit_1 | [`jdvUwM9XREVf8xVLCTdtzNzdUsojYMzs4vt9KfC3VMShFGRoUUn2URtn8NubpDTV4D8b6msm6m8U7VRcN8i2M2h`](https://explorer.solana.com/tx/jdvUwM9XREVf8xVLCTdtzNzdUsojYMzs4vt9KfC3VMShFGRoUUn2URtn8NubpDTV4D8b6msm6m8U7VRcN8i2M2h?cluster=devnet) | Finalized | 38974 |
| crowd_commit_2 | [`26NePoSsexrV19xhSv4DAghmfnqnq8Ta4ANjP2CQf5AHiNcekminPTainRfa1t3dg1LzoYrhyJWXyp2ou2eZnw18`](https://explorer.solana.com/tx/26NePoSsexrV19xhSv4DAghmfnqnq8Ta4ANjP2CQf5AHiNcekminPTainRfa1t3dg1LzoYrhyJWXyp2ou2eZnw18?cluster=devnet) | Finalized | 38959 |
| crowd_commit_3 | [`59vt1jTis7Tmwht5bur3VdU9EXAxGUaANQ74pEwdAABo324A2oyrNQgwDcDpuCuFYFqEvuGEPD1MXMfy41zUoMhn`](https://explorer.solana.com/tx/59vt1jTis7Tmwht5bur3VdU9EXAxGUaANQ74pEwdAABo324A2oyrNQgwDcDpuCuFYFqEvuGEPD1MXMfy41zUoMhn?cluster=devnet) | Finalized | 38967 |
| underfloor_commit_0 | [`4krPmZHt5FXwMVAE5AS3YYVF4e29pxokqYKUhNCtDPbAii4ws63CDTetgD4syWvc3WcM4V1r96a4txQY4jX81MmG`](https://explorer.solana.com/tx/4krPmZHt5FXwMVAE5AS3YYVF4e29pxokqYKUhNCtDPbAii4ws63CDTetgD4syWvc3WcM4V1r96a4txQY4jX81MmG?cluster=devnet) | Finalized | 44824 |
| underfloor_commit_1 | [`4WATKSq7aRzBwu4Us5CpjXDyzH7k8d7WAmEy3m8JRaU1CaKrECrzZFYZg1nczDzwjyLgqxJE6HQF7cS8LK6wbgMy`](https://explorer.solana.com/tx/4WATKSq7aRzBwu4Us5CpjXDyzH7k8d7WAmEy3m8JRaU1CaKrECrzZFYZg1nczDzwjyLgqxJE6HQF7cS8LK6wbgMy?cluster=devnet) | Finalized | 43467 |
| crowd_settle | [`5z4PLdcuVtPJ58vEWUrxBjGbPBuQhy4ez4NDB7p9jsMUfhm9sE4YM9znoeLrKNQ5Hpau6sHiXiojEhpB5R82SSKV`](https://explorer.solana.com/tx/5z4PLdcuVtPJ58vEWUrxBjGbPBuQhy4ez4NDB7p9jsMUfhm9sE4YM9znoeLrKNQ5Hpau6sHiXiojEhpB5R82SSKV?cluster=devnet) | Finalized | 18733 |
| zk_deposit_commit | [`41sUBaZbpmXmStBF8QdJrFu72sqzoYVMUKm92hM2g1uvGmfRvegUdrskxzerYXTvJfhngfQ2XRwiHkBCZJHtXNz7`](https://explorer.solana.com/tx/41sUBaZbpmXmStBF8QdJrFu72sqzoYVMUKm92hM2g1uvGmfRvegUdrskxzerYXTvJfhngfQ2XRwiHkBCZJHtXNz7?cluster=devnet) | Finalized | 40957 |
| zk_settle | [`y8woZ1Y5RsvojGiQbssbWPqpHuhFngVFfbz13eZDRLgXqzd3CAhT6KQkHvw9iggx6yDaVD6p35Jpte3diSCwKiz`](https://explorer.solana.com/tx/y8woZ1Y5RsvojGiQbssbWPqpHuhFngVFfbz13eZDRLgXqzd3CAhT6KQkHvw9iggx6yDaVD6p35Jpte3diSCwKiz?cluster=devnet) | Finalized | 106101 |

## Confidential-value soak - shield / transfer / unshield (devnet)

Fresh pools per run. The 2-in/2-out JoinSplit `Transact` layer, driven by the
participant CLI (in-process `ark-circom`/`ark-groth16` proving, no Node process,
under the phase-2 CEREMONY proving key) and the gasless coordinator. A transfer
is signed ONLY by the relay (hides WHO for that transfer) and carries
`publicAmount == 0` (hides HOW MUCH).

- main ValuePool: `DfsDNKnxD4vZS59y9SrUhs3LbEb2U6QDsAApRMc5tYZT` (authority / relay `4yS9DANyA4UqFjVwKr6GMyYcQ7cYNdWZ8tsMAwidVnDa`), vault `7DNtZtnk5hqvcUtGddUStq4GBR2KsfDP6gNPF1eSBXrs`
- main pool (Explorer): https://explorer.solana.com/address/DfsDNKnxD4vZS59y9SrUhs3LbEb2U6QDsAApRMc5tYZT?cluster=devnet
- fixed-denomination ValuePool: `29KXP7mx7Hz87NLErLida55PnMs1HyVqJYdyRJBhiicc` (denomination 10000000 lamports)
- relay fee bound into ext-data: 5000 lamports
- amounts: shield 50000000 lamports, hidden transfer 20000000 lamports, withdraw 20000000 lamports

### On-chain assertions (27/27)

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq |
| PASS | JoinSplit verifying key published into its write-once registry PDA | init_vk: already published (registry holds exactly the committed key) |
| PASS | main ValuePool initialized (authority=relay, fee set, no denom) | vpool=DfsDNKnxD4vZS59y9SrUhs3LbEb2U6QDsAApRMc5tYZT vault=7DNtZtnk5hqvcUtGddUStq4GBR2KsfDP6gNPF1eSBXrs fee=5000 denom=None cc=0 |
| PASS | fixed-denom ValuePool initialized (denomination pinned) | vpool=29KXP7mx7Hz87NLErLida55PnMs1HyVqJYdyRJBhiicc vault=3YweGZN1Bk4QAdHsfXujz7rMazYRhtqkHXheuQkWwQ7L denom=Some(10000000) |
| PASS | value-pool ALT created + extended (keeps a Transact inside one packet) | alt=6ZspFXx1Zxe3mv1gdT3vWJgyVioTgxA4NdHdmEUu8Q5x (7 shared accounts) |
| PASS | shield proof generated + verified (in-process ark-groth16) and emitted | mirror-cli shield produced a Transact whose proof it generated and verified in-process |
| PASS | vault credited by the shielded deposit amount | vault delta 50000000 lamports (= shield 50000000) |
| PASS | value root advanced + both output commitments inserted | commitment_count 0->2, root changed |
| PASS | both input nullifier PDAs created (anti-replay) | nf0=6obWfiXJ78CEoLoWWSm9M6akmAUDz8cA4UdwWn9PkGPv nf1=GHPW9aVZymYk3E3us5w2sffUknxYks1PrrnDMYha2Td both program-owned + spent |
| PASS | shield publicAmount encodes the deposit magnitude (public deposit) | publicAmount=0000000000000000000000000000000000000000000000000000000002faf080 |
| PASS | shield replay rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x3; 7 log messages:   Program ComputeBudget111111111111111111111111111111 invoke [1]   Program Co |
| PASS | Alice scan recovered a SPENDABLE note from the enc blobs | recovered note .soak/notes-value/value-2854acb9a3d2d2b4d9501601ead17765b9f843d98257a34f6a86ce1f177d9c2c.json (spendable=true) |
| PASS | transfer carries NO cleartext amount (publicAmount == 0) | publicAmount=0000000000000000000000000000000000000000000000000000000000000000 |
| PASS | on-chain Transact bytes carry a zeroed publicAmount for the transfer | transact_data[1..33] (publicAmount) is 32 zero bytes |
| PASS | mutated public input rejected (ProofVerificationFailed) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0xc; 11 log messages:   Program ComputeBudget111111111111111111111111111111 invoke [1]   Program C |
| PASS | transfer advanced the value root (2 new output commitments) | commitment_count 2->4, root changed |
| PASS | transfer moved NO public lamports (vault unchanged) | vault 50890880 -> 50890880 |
| PASS | transfer created new nullifier PDAs (input note spent) | nf0=4vmFWv8fkimsTggqqxPR5epALyF5At3JR3WKUsz47HV3 nf1=DcDSfM95wycW7fgjDm75cAx2wB8mDg7QFg7M7u6x93PF both program-owned + spent |
| PASS | Bob scan auto-discovered his payment note (recipient-directed) | recovered note .soak/notes-value/value-1f60096d68b2e6b9a42dfbeb0c66b79c33c0adb68232ad9d8e4b65b524d2e1a1.json (spendable=true) |
| PASS | fresh recipient credited by the withdrawn amount | recipient D2jm39yLo4pSE4ZzEcmwP58QwiSbde7nVVMi7pFpbn5j credited 20000000 lamports (= withdraw 20000000) |
| PASS | vault debited by exactly the withdrawn amount | vault debited 20000000 lamports |
| PASS | unshield advanced the value root | commitment_count 4->6, root changed |
| PASS | unshield created the input nullifier PDA (anti-replay) | nf0=GEivfs8LbS36HTLLFx8jMcL3DNW3VSpeCcpqpjEYcpfh program-owned + spent |
| PASS | fixed-denom shield of EXACTLY the denomination succeeds | vault2 credited 10000000 lamports (= denomination 10000000) |
| PASS | on-chain: wrong-denomination deposit rejected (DenominationMismatch) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x17; 7 log messages:   Program ComputeBudget111111111111111111111111111111 invoke [1]   Program C |
| PASS | CLI fail-fast: wrong-denomination shield refused client-side | Error: this value pool pins a fixed denomination of 10000000 lamports; a public deposit/withdraw must move exactly that amount (got 10000001)  |
| PASS | main vault balance == net public deposit - net public withdrawal | vault 30890880 == baseline 890880 + (shield 50000000 - withdraw 20000000) = 30890880 |

Two of those rows are new since the pre-registry runs. The first is the
verifying-key publication. The second is the Address Lookup Table: a `Transact`
carries a 256-byte proof, seven 32-byte public inputs and two encrypted-note
blobs, and now that the verifying key lives in a registry account the
instruction takes one account more than it used to, which pushes the inline form
past the 1232-byte packet limit. The table holds only the accounts that are
identical in every `Transact` against these pools; the nullifier PDAs and the
signers stay inline. It changes packing, not the instruction and not the signers.

### Finalized transaction signatures + compute units

| flow | signature (Explorer) | commitment | CU consumed |
| --- | --- | --- | --- |
| init_vk_transaction | [`61ysGZNmMYNwNgZSsLGTJuargPezabCYnpAKjU33BhXkcVYWedUkow8GF2b9gQ4eMpa3SJeJLPFzgqRrgNjYbWWe`](https://explorer.solana.com/tx/61ysGZNmMYNwNgZSsLGTJuargPezabCYnpAKjU33BhXkcVYWedUkow8GF2b9gQ4eMpa3SJeJLPFzgqRrgNjYbWWe?cluster=devnet) | Finalized | 4108 |
| init_value_pool_main | [`hisSrjfhKRofCJjbHqcoqUF75zpnbGAMhuRftAFuX1xWaYKBc7F7XkufKqTf5TQt7fgbjySamVG15Hf7B6MXbb4`](https://explorer.solana.com/tx/hisSrjfhKRofCJjbHqcoqUF75zpnbGAMhuRftAFuX1xWaYKBc7F7XkufKqTf5TQt7fgbjySamVG15Hf7B6MXbb4?cluster=devnet) | Finalized | 24476 |
| init_value_pool_denom | [`25xq33zvKJVhnFHVvEDRiYpa9A6wvrXUcjcsVSdJk6P7TWXuUh9G16RSH3RXK6sJjt8Ybs3t1SdmE6hQbqP75hp5`](https://explorer.solana.com/tx/25xq33zvKJVhnFHVvEDRiYpa9A6wvrXUcjcsVSdJk6P7TWXuUh9G16RSH3RXK6sJjt8Ybs3t1SdmE6hQbqP75hp5?cluster=devnet) | Finalized | 23015 |
| shield | [`5UMRL4RwvgDzZVwNdgwiavQ1SKZK14XUVvDQNeTjoV8BfUe4R4TxkvcJgcz1k7WqRFcZzAMwYKBfLqBCDguACZP3`](https://explorer.solana.com/tx/5UMRL4RwvgDzZVwNdgwiavQ1SKZK14XUVvDQNeTjoV8BfUe4R4TxkvcJgcz1k7WqRFcZzAMwYKBfLqBCDguACZP3?cluster=devnet) | Finalized | 198587 |
| transfer | [`5VBg5XuiQu1D9AxaqpHGf5s5GeYPsZhsJYHW1eyER32UQDgXUqtBc1U9y2m6vejwnSiuHRLxiGDxRb6hEEXwg3fp`](https://explorer.solana.com/tx/5VBg5XuiQu1D9AxaqpHGf5s5GeYPsZhsJYHW1eyER32UQDgXUqtBc1U9y2m6vejwnSiuHRLxiGDxRb6hEEXwg3fp?cluster=devnet) | Finalized | 193946 |
| unshield | [`4o1csm2xpoyCkpoF1P812Drzax1tEUNsLkQdTQW4L6ecpc23SsSP6Jk3ovkAPVNDnypprfM2y1Wki9hQquytfwB6`](https://explorer.solana.com/tx/4o1csm2xpoyCkpoF1P812Drzax1tEUNsLkQdTQW4L6ecpc23SsSP6Jk3ovkAPVNDnypprfM2y1Wki9hQquytfwB6?cluster=devnet) | Finalized | 195713 |
| denom_shield_exact | [`2pxRmiFBKSGMAfHDvkMY1zxUGmiig9rd2Bdfix4VRsgZynNcWFb6ZpmAYXsHyGDMHzZUyQBCpZEZ8i3fH9EsV8R4`](https://explorer.solana.com/tx/2pxRmiFBKSGMAfHDvkMY1zxUGmiig9rd2Bdfix4VRsgZynNcWFb6ZpmAYXsHyGDMHzZUyQBCpZEZ8i3fH9EsV8R4?cluster=devnet) | Finalized | 205407 |

### Reproduce (devnet)

```sh
# 1. build
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. a fresh program keypair + a single funded master payer (.soak/, gitignored)
solana-keygen new -o .soak/keys/devnet-program.json
solana-keygen new -o .soak/keys/devnet-funder.json
solana airdrop 2 $(solana address -k .soak/keys/devnet-funder.json) --url devnet

# 3. deploy to public devnet
solana program deploy --url https://api.devnet.solana.com \
  --keypair .soak/keys/devnet-funder.json \
  --program-id .soak/keys/devnet-program.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 4. run both soaks against devnet, funding every key by system-transfer
#    from the one master payer (no per-key airdrops). Each publishes its
#    circuit's verifying key through `init-vk` first, and proves under the
#    phase-2 ceremony key in ceremony/<circuit>/ (gitignored; see CEREMONY.md).
PROG=$(solana address -k .soak/keys/devnet-program.json)
export MIRROR_FUNDING_KEYPAIR=$PWD/.soak/keys/devnet-funder.json
MIRROR_PROOF_JSON=$PWD/.soak/behavioral.json cargo run -p mirror-soak -- \
  --rpc-url https://api.devnet.solana.com --program-id $PROG \
  --epoch-slots 128 --k-floor 3 --zk-amount 50000000
MIRROR_PROOF_JSON=$PWD/.soak/confidential.json \
  cargo run -p mirror-soak --bin mirror-soak-value -- \
  --rpc-url https://api.devnet.solana.com --program-id $PROG \
  --shield-amount 50000000 --transfer-amount 20000000 --denomination 10000000
```

The two `.soak/*.json` reports each carry every assertion and every signature, so
the tables above are re-derivable from a run rather than hand-maintained. The
`Finalized` column and the CU figures come from `solana confirm -v` over those
signatures afterwards.

---

# Local Surfpool run (mainnet mirror)

The two runs below are against a LOCAL Surfpool validator (a local mainnet
mirror), kept for completeness. Their signatures are local-validator signatures,
reproducible by re-running the soak against a fresh Surfpool, and are NOT
lookups on a public explorer (unlike the devnet section above).

**These two are HISTORICAL: they were captured against older bytecode and have
NOT been re-run.** They are left exactly as recorded. The behavioral and
confidential suites were re-run against the current bytecode on devnet, above;
the only local suite that was re-run against the current bytecode is the
funding-round soak at the bottom of this file.

This documents an automated end-to-end run of `mirror-soak` against a LIVE local
Surfpool validator (a local mainnet mirror at `http://127.0.0.1:8899`), treated as mainnet. It is NOT
a public deploy: the transaction signatures below are local-validator signatures, so
they are reproducible by re-running the soak against a fresh Surfpool, not lookups on a
public explorer.

- generated: unix 1784268425
- program id: `7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve`
- pool PDA: `B8p6mYz3BX419wD7W6NQ5yQsATR7pPvCsYYyv9X5HEQX` (authority / relay `GNhKEn5283uPKhvnS6ZXgUyRN2gMz6gGV2waVeeDxuWt`)
- pool config: epoch_slots=64, k_floor=3, entry_fee=1000000 lamports, reward_bps=2500
- reward pool accrued from entry fees at end of run: 1750000 lamports
- total leaves appended: 7

## What was exercised

1. **Setup** - airdrop relay + payer, ensure the program is deployed, `InitPool`
   a fresh pool with a nonzero entry fee + reward split, and create the pool ALT.
2. **Crowd path (PlainTransfer)** - 4 participants commit the SAME action into one
   shared epoch; after the window closes the gasless coordinator
   (`RpcSettleSubmitter`) settles ONE atomic transaction: ComputeBudget +
   `SettleEpoch` + 4 identical System transfers.
3. **ZK opt-in path** - `mirror-cli deposit-commit` escrows to a FRESH recipient;
   after the window closes `mirror-cli prove` generates a snarkjs-verified Groth16
   membership proof and the relay submits `SettleZk`, moving the escrow to the
   fresh recipient.
4. **Adversarial** - under-floor epoch does not settle (on-chain `BelowKFloor` +
   off-chain coordinator roll-forward); duplicate crowd nullifier rejected
   (`NullifierSpent`); re-settle rejected (`EpochAlreadySettled`); ZK settle to a
   mismatched recipient rejected (`ActionHashMismatch`); ZK replay rejected
   (`NullifierSpent`).

## On-chain assertions

17/17 assertions passed.

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve |
| PASS | pool initialized with fixed config | version=1 epoch_slots=64 k_floor=3 entry_fee=1000000 authority=relay |
| PASS | pool ALT created + extended | alt=8gWfGfEcT9HUBYtWzKoSNn8xUJViwZmJffy7wBd7pqpy (6 shared accounts) |
| PASS | 4 commits batched into one shared epoch | epoch_id=69 commit_count=4 settled=false |
| PASS | duplicate crowd nullifier rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x3: 5 log messages: Program 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve invoke [1] Program 11111 |
| PASS | crowd epoch marked settled on-chain | epoch_id=69 settled=true |
| PASS | 4 nullifier PDAs created (anti-replay) | 4/4 nullifier PDAs exist and are program-owned |
| PASS | 4 identical transfers executed atomically | sink credited 40000000 lamports (= 4 x 10000000 bucket) |
| PASS | re-settle of a settled epoch rejected (EpochAlreadySettled) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x6: 3 log messages: Program 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve invoke [1] Program 7vUgz |
| PASS | under-floor epoch rejected on-chain (BelowKFloor) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x2: 3 log messages: Program 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve invoke [1] Program 7vUgz |
| PASS | under-floor epoch rolled forward off-chain (coordinator) | coordinator.on_slot returned RolledForward (real_k < k_floor) |
| PASS | Groth16 membership proof generated + verified (snarkjs) | mirror-cli prove produced a snarkjs-verified SettleZk |
| PASS | SettleZk authority == pool relay | authority=GNhKEn5283uPKhvnS6ZXgUyRN2gMz6gGV2waVeeDxuWt |
| PASS | ZK settle to mismatched recipient rejected (ActionHashMismatch) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0xe: 3 log messages: Program 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve invoke [1] Program 7vUgz |
| PASS | escrow landed at the FRESH recipient | recipient credited 250000000 lamports (= escrow 250000000) |
| PASS | ZK nullifier PDA created (anti-replay) | nullifier PDA CSEcsBsw2atbPRPYvrHJdRtwwz8npbZHNca5q92RR5Y1 exists + program-owned |
| PASS | ZK replay rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x3: 3 log messages: Program 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve invoke [1] Program 7vUgz |

## Captured transaction signatures

| step | signature |
| --- | --- |
| init_pool | `3sJzBfFx9GmrHhCwaSWhXxxPiRxDFgU3BQnXjq7t58sqVFVVjDc2qLVT3mYg3ATThP8d8sNcfuSrcj5gGqNvEaBd` |
| crowd_commit_0 | `2FZ84WP5zMhDYa6q1NMHty6NfgiUYpYQXjQfPbpiLC68jf9NheTyk7WFPXzgpCMwB7Nk55CYDdpFeWgxv8fPUjLs` |
| crowd_commit_1 | `2Di35RYAycEENrC1Jm67qsTjwJvpJJgBKdbXzkC2cvAFJPfxZ7yTYNkpZNssfi8sc5PJZwrJM8qvErQwyxFfcD9r` |
| crowd_commit_2 | `5AgcNeb3U8oXuTNBjSRWr4vVMsWGELvGkhU5w9vqpcE83D3Wniip9BN2p26CQqHoRTukXw9makjVLtzp4nRmneKv` |
| crowd_commit_3 | `3mTEb3fzs5K5LhfqGmJva45ejx4sdFCUnBivqyMwWdDnkawJiYx33xU9cLKbW8kBvEp6PX49h7aQAwzgAMPnLUKg` |
| underfloor_commit_0 | `5tBxnys1uML8LHZpLpyMW8GAE8dZtkUVVzSk7M1TmPhobjaB3EVncitkj4u9V2Hcj2nDUbT1K2wAR2VNzqgu3FWC` |
| underfloor_commit_1 | `2yDBXF9qNQLdmB4dzZDowzzuddxv8Z1CbpLgDseQUzjUwJf1AQByNNd4wzm2S8E8oWVvBu731eDzNCak7ooRiq8` |
| crowd_settle | `3yeoJxJ7ofsZ9beaRt2CosUg1DA8FSvcdj4F4qdGRxMFjVqWFioLpHFVbu9vthwjtHzBC72kWYVzSbmgXQti884J` |
| zk_deposit_commit | `XFiuwcC3dSppY65D1hMt6htuCvmnoLPwxHoDdFkoN784megCWcNQKLjqJcF5SgehRewBdQXU34YTK8EgFjAiZFW` |
| zk_settle | `44mkW9B4qJVwP4uC7jDNXDt4RccqC5svrR54uFmSz3s46RMdGcdC1Yy74aFSXxn7sRiDkrBwKh61aSiv5WWCAytZ` |

## Reproduce

With a local Surfpool running at `http://127.0.0.1:8899` (treated as mainnet):

```sh
# 1. build the on-chain program and the host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program (the soak also does this if it is missing)
solana program deploy \
  --url http://127.0.0.1:8899 \
  --program-id programs/mirror-pool/target/deploy/mirror_pool-keypair.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. (ZK path) ensure the circuit artifacts are present (proving is in-process
#    pure Rust; circom/snarkjs are only needed to BUILD these artifacts)
#    circuits/membership_final.zkey, circuits/membership_js/membership.wasm,
#    circuits/artifacts/verification_key.json  (build with `bash circuits/build.sh`)

# 4. run the soak (it auto-deploys if missing and defaults --program-id to the
#    built keypair's pubkey, so a fresh clone needs no id passed)
cargo run -p mirror-soak -- \
  --rpc-url http://127.0.0.1:8899 \
  --epoch-slots 64 --k-floor 3
```

Every run creates a fresh pool (a fresh relay authority), so the run is
self-contained and repeatable; the signatures above are from this run.

<!-- confidential-value-soak:begin -->
## Confidential-value soak

This section documents an automated end-to-end run of `mirror-soak-value` (the
confidential-VALUE soak) against a LIVE local Surfpool validator (a local mainnet
mirror at `http://127.0.0.1:8899`), treated as mainnet and run honestly. It exercises the 2-in/2-out
JoinSplit `Transact` layer (shield / transfer / unshield) through the SHIPPED
participant CLI (`mirror-cli`, which proved with snarkjs at the time of this run and
emits each Transact; it now proves in-process in pure Rust by default) and
the gasless coordinator (`mirror_coordinator::submit_transact`). The signatures below
are local-validator signatures, reproducible by re-running the soak against a fresh
Surfpool, not lookups on a public explorer.

- generated: unix 1784419802
- program id (fresh deploy): `BDhUdkZeHrk1cNG2Yss6Z5jTMHEkqqvPiJJTAZSSmFti`
- main ValuePool: `HGXEAGVAk1oAZqtsmKktJXCRzEVWeLmpvuZ9PsaB7RUd` (authority / relay `3pBAG4Qas7iSQWP6Zk2gei3feV9LdmTBkjPYdedN4BaC`), vault `9Bex8sCeF2WxxvFxBtK8V6LiyXbBLdEKR6oc56kzFcoR`
- fixed-denomination ValuePool: `8jCZ3GssRGoXXmERfKJRo4oAiiKwuZiS1jhb1xwRoWwb` (denomination 100000000 lamports)
- relay fee bound into ext-data: 5000 lamports (nonzero)
- amounts: shield 500000000 lamports, hidden transfer 200000000 lamports, withdraw 200000000 lamports

### What was exercised

1. **Setup** - airdrop a relay/authority + payer + depositor; `InitValuePool` a main
   pool (nonzero fee) and a second pool with a fixed `denomination`.
2. **Shield** - Alice `value-keygen`; shield Alice->Alice for `v`, submitted co-signed
   by the depositor. The vault is credited by `v`, the value root advances, both output
   commitments are inserted, and both input nullifier PDAs are created. A replay is
   rejected (`NullifierSpent`).
3. **Scan + private transfer** - Alice `scan`s the emitted `enc` blobs against the
   on-chain leaves to recover a spendable note, then `transfer`s a HIDDEN amount to Bob
   (`publicAmount == 0`), submitted gasless (relay-only signer). The root advances, new
   nullifier PDAs are created, and the on-chain Transact carries NO cleartext amount. A
   mutated public input is rejected (`ProofVerificationFailed`).
4. **Unshield** - Bob `scan`s -> recovers his note; `unshield` Bob->a FRESH recipient
   for `w`, submitted gasless. The fresh recipient is credited by `w`, the vault is
   debited by `w`, and the nullifier PDA exists.
5. **Fixed-denomination** - a shield of exactly the denomination succeeds; a Transact
   whose public deposit magnitude differs is rejected on-chain
   (`DenominationMismatch`), and the CLI fail-fasts the same case client-side.
6. **Conservation** - the vault balance equals the net public deposit minus the net
   public withdrawal (a transfer moves no public lamports).

This proves the headline claim: mirror-pool hides both WHO initiated (a transfer /
unshield is signed ONLY by the gasless relay, never the acting wallet) AND HOW MUCH
(a transfer's on-chain `publicAmount` is zero; amounts live only inside commitments and
encrypted note blobs).

### On-chain assertions

25/25 assertions passed.

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | BDhUdkZeHrk1cNG2Yss6Z5jTMHEkqqvPiJJTAZSSmFti |
| PASS | main ValuePool initialized (authority=relay, fee set, no denom) | vpool=HGXEAGVAk1oAZqtsmKktJXCRzEVWeLmpvuZ9PsaB7RUd vault=9Bex8sCeF2WxxvFxBtK8V6LiyXbBLdEKR6oc56kzFcoR fee=5000 denom=None cc=0 |
| PASS | fixed-denom ValuePool initialized (denomination pinned) | vpool=8jCZ3GssRGoXXmERfKJRo4oAiiKwuZiS1jhb1xwRoWwb vault=GhJdTbbwRgrWVCv9yMuA6f7jHQN7P7Eic83ZCCCsxPqv denom=Some(100000000) |
| PASS | shield proof generated + verified (snarkjs) and emitted | mirror-cli shield produced a snarkjs-verified Transact |
| PASS | vault credited by the shielded deposit amount | vault delta 500000000 lamports (= shield 500000000) |
| PASS | value root advanced + both output commitments inserted | commitment_count 0->2, root changed |
| PASS | both input nullifier PDAs created (anti-replay) | nf0=2XaYECkreoWRk6b1oggeb7m6NsefU5NE9f5irWFoA2E6 nf1=CpAhAPmG1B7buFMhowk3pCh8VszbJiosRHQicm4cm8gY both program-owned + spent |
| PASS | shield publicAmount encodes the deposit magnitude (public deposit) | publicAmount=000000000000000000000000000000000000000000000000000000001dcd6500 |
| PASS | shield replay rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x3: 7 log messages: Program ComputeBudget111111111111111111111111111111 invoke [1] Program Comput |
| PASS | Alice scan recovered a SPENDABLE note from the enc blobs | recovered note .soak/notes-value/value-28c794b627ef7973b8737cd27f2564d0f1fceca3b1f9fb11dcc6155a125604ff.json (spendable=true) |
| PASS | transfer carries NO cleartext amount (publicAmount == 0) | publicAmount=0000000000000000000000000000000000000000000000000000000000000000 |
| PASS | on-chain Transact bytes carry a zeroed publicAmount for the transfer | transact_data[1..33] (publicAmount) is 32 zero bytes |
| PASS | mutated public input rejected (ProofVerificationFailed) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0xc: 11 log messages: Program ComputeBudget111111111111111111111111111111 invoke [1] Program Compu |
| PASS | transfer advanced the value root (2 new output commitments) | commitment_count 2->4, root changed |
| PASS | transfer moved NO public lamports (vault unchanged) | vault 500890880 -> 500890880 |
| PASS | transfer created new nullifier PDAs (input note spent) | nf0=3XXRMvuUGdZNHHPeBw5Ky798LjzHdCnN3f5QhVZXDkbx nf1=GF4sZMEoDirKpaBhdooevKP2GctGVv5AyWm4rUChYBfq both program-owned + spent |
| PASS | Bob scan auto-discovered his payment note (recipient-directed) | recovered note .soak/notes-value/value-28eeb3512c04468d96ee2fe83b0f4ec66b6b5182d3023dddc27f2e3bc37971f7.json (spendable=true) |
| PASS | fresh recipient credited by the withdrawn amount | recipient kD68zh32B1d1ncEa7iitCSXrHFj4DixyhETaKKnNhBw credited 200000000 lamports (= withdraw 200000000) |
| PASS | vault debited by exactly the withdrawn amount | vault debited 200000000 lamports |
| PASS | unshield advanced the value root | commitment_count 4->6, root changed |
| PASS | unshield created the input nullifier PDA (anti-replay) | nf0=BMsfP4FtpMuB8LS4UXF6CUnJuMiDh4gnMTSEJhSLyDyV program-owned + spent |
| PASS | fixed-denom shield of EXACTLY the denomination succeeds | vault2 credited 100000000 lamports (= denomination 100000000) |
| PASS | on-chain: wrong-denomination deposit rejected (DenominationMismatch) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x17: 7 log messages: Program ComputeBudget111111111111111111111111111111 invoke [1] Program Compu |
| PASS | CLI fail-fast: wrong-denomination shield refused client-side | Error: this value pool pins a fixed denomination of 100000000 lamports; a public deposit/withdraw must move exactly that amount (got 100000001)  |
| PASS | main vault balance == net public deposit - net public withdrawal | vault 300890880 == baseline 890880 + (shield 500000000 - withdraw 200000000) = 300890880 |

### Captured transaction signatures

| step | signature |
| --- | --- |
| init_value_pool_main | `5udFU85WWNU6AimmqRGev1hwzMeCzxFTpepS8TW1fqhtHW7Q67nMogg3wgox4PBozd9bAi3N7NrpZ2jFyTqi9Bne` |
| init_value_pool_denom | `4cR5g3nyishMKYDza1X8DYhwyp8hcV1ShJK4zbpxTXiqL9eptZp3Q7ZjVCxVMH9aHLCZMWySEiihFqgWpJy7747u` |
| shield | `o57DZznAhcH7mXxxwwnRY751VvuPrUivMt17pc9Jz7nM3ATBQYNuhFiHitFUibRmPbo1fKsfE8HD8ufqyHhq9T2` |
| transfer | `4XNFRnoo5pEqYUr46uk6uVtcGCncMFR5H2H59VcpF5yZz2sUfxFxuR1cjNVdbLhiVbftRW1btvW5hgbyKnsSJGAe` |
| unshield | `2XNLaht9pPykvzdrTiBeCJYEmLwJVaYnM4qVVZEAndJVT6U2KAsA68eCupNrDqcCcJ9Mh3QE1tWwSSuMUCrwQMZW` |
| denom_shield_exact | `2A5Lg3oyHL9f1zj3knxpDTLDWRuWhfjJjb7XubJ3Zzxo3L7xsDeM2jjjfoAdCBknYdoR2bpjvVbtyDAhzf2Bzfj3` |

### Reproduce

With a local Surfpool running at `http://127.0.0.1:8899` (treated as mainnet):

```sh
# 1. build the on-chain program + host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program under a FRESH program id
solana-keygen new -o .soak/keys/confidential-program.json
solana program deploy \
  --url http://127.0.0.1:8899 \
  --program-id .soak/keys/confidential-program.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. ensure the transaction-circuit artifacts are present (proving is in-process
#    pure Rust; circom/snarkjs are only needed to BUILD these artifacts)
#    circuits/transaction_final.zkey, circuits/transaction_js/transaction.wasm,
#    circuits/artifacts/transaction_verification_key.json

# 4. run the confidential-value soak against the id you just deployed
cargo run -p mirror-soak --bin mirror-soak-value -- \
  --rpc-url http://127.0.0.1:8899 \
  --program-id "$(solana address -k .soak/keys/confidential-program.json)"
```

Every run creates fresh pools (fresh relay authorities) and fresh wallets, so the run
is self-contained and repeatable; the signatures above are from this run.

---

# Trusted-setup ceremony - local demonstration run

Recorded 2026-07-27 on the membership circuit, plus an independent second run on the
transaction circuit. This is a **demonstration that the ceremony machinery works end
to end**, NOT a production ceremony: every contribution came from one machine, so the
tool reports one independent contributor; the beacon source is a fixed demo string
rather than a value nobody could predict; and this run's key was never deployed.

> **Superseded, for all three circuits.** Separate, later ceremonies - closed by
> real public Solana mainnet-beta blockhashes rather than a demo string - produced
> every key that is committed and deployed today. They are recorded in
> "Trusted-setup ceremony - the DEPLOYED keys" further down, and in
> `docs/CEREMONY.md` section 10. Everything in *this* section is the earlier
> demonstration run, kept as captured. Where the text below says "the committed
> verifying key" it means the dev key that was committed at the time of capture;
> `circuits/artifacts/*verification_key.json` today holds ceremony keys, so the
> `snarkjs groth16 verify` transcript below would no longer reproduce verbatim
> against those paths.

**The transcripts of this run are committed**, at
`docs/ceremony-run/membership-transcript.json` (7 KB) and
`docs/ceremony-run/transaction-transcript.json` (6 KB). Section "What a third party
can check" below states exactly what they do and do not let an outsider reproduce.

## What the ceremony was anchored to

| item | value | reproducible? |
| --- | --- | --- |
| phase 1 | `pot16_final.ptau`, sha256 `1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922` | yes - a public file |
| phase-1 provenance | 55 contributions, power `2^16`, ceremony power `2^28`, named contributors | yes - `ceremony inspect-ptau` reads them out of the file |
| circuit | `circuits/membership.r1cs`, sha256 `8ed379951ad0b7371b4ac53fc373b64c36ac26552802ff165dad7af4977bd0a2` | yes, for a given circom version |
| initial phase-2 key | sha256 `8c6b6c48195a4e116322cace04ec7619a9b158137bb98df37d9f78e651b15697` | **yes** - `snarkjs groth16 setup` is deterministic |
| beacon source | the text `mirror-pool demo beacon 2026-07-27`, `2^16` SHA-256 iterations | yes - published here, which is what makes check 12 runnable |

The determinism of `snarkjs groth16 setup` was checked directly: running it twice on
the same r1cs and ptau produced byte-identical zkeys
(sha256 `57f5131bdff513f685b39323d44471821a431447b6fb749f81d5bef4bbea0afe`), matching
the `membership_0000.zkey` the build script emits. That is what lets a verifier
re-derive the start of the chain instead of trusting it.

## The chain

| step | contributor | kind | entropy | new key digest (first 16) | chain hash (first 16) |
| --- | --- | --- | --- | --- | --- |
| 0 | `alice@example.org` | entropy | OS + user string | `30bb22b26bf366bc` | `02cf868b07c2eff9` |
| 1 | `bob@example.net` | entropy | OS + user string | `1bc5b1cf0c371e5e` | `d9643bce149db23a` |
| 2 | `carol@example.com` | entropy | OS + user string | `4d9886284e11a877` | `dde23ec7e626d151` |
| 3 | `coordinator` | beacon (`2^16` SHA-256 iterations) | public | `d120a789e077a4f5` | `4704bc3af3dbd387` |

Final ceremony hash: `4704bc3af3dbd387fe24f831a3a951882373e05222278b3f4337dd50c7681049`.
Transcript file sha256: `ff2af0bd07e77182629b063e71f07d28282cd1e08720c102b348bf869302d5da`.

Contribution digests are **not** reproducible by a third party: the scalars come from
OS randomness, which is the point. What a third party reproduces is the *verification*.

## What verification reported

`mirror-cli ceremony verify --dir ... --r1cs ... --initial-zkey ... --beacon-source-text ...`:

```
r1cs circuits/membership.r1cs matches the transcript.
initial key re-derived from circuits/membership_0000.zkey matches the transcript.
CEREMONY VERIFIED
  steps:                   4
  of which beacons:        1
  closed by beacon:        yes
  beacon pre-commitment:   checked against the value you supplied
  final transcript hash:   4704bc3af3dbd387fe24f831a3a951882373e05222278b3f4337dd50c7681049
  phase-1 contributions:   55

INDEPENDENT CONTRIBUTORS: 1
  from 4 step(s): 3 with secret entropy, 0 deterministic, 1 beacon
  [counted] alice@example.org (steps 0, 1, 2, 3)
        merged: 0 and 1: same machine fingerprint
        ...
WARNINGS
  - 1 beacon step(s) present; a beacon removes last-mover grinding but adds no
    secrecy, so it is NOT counted as an independent contributor
  - only 1 independent contributor: safety rests entirely on that one party having
    destroyed their scalar
  - contributions 0 and 1 are 2s apart, which is fast for an out-of-band handoff
```

**Three distinct self-asserted identities, one machine, reported as one contributor.**
That is the self-run refusal doing its job on a real run, and it is why the headline
number in this section is 1 and not 3.

Run the same command *without* `--beacon-source-text` and the report changes in two
places, which is the point of publishing the beacon value:

```
  beacon pre-commitment:   NOT supplied - a relabelled beacon cannot be ruled out
  - no pre-committed beacon value was supplied to this verification, so it cannot
    rule out that a step counted as a secret contribution was a relabelled public
    beacon; re-run with the beacon value the ceremony announced in advance
```

## The rules the run had to satisfy

Both of these are enforced by the code as of this run, and both are exercised
adversarially in `crates/mirror-ceremony/tests/ceremony.rs`:

```
$ mirror-cli ceremony contribute --dir "$D" --id "late-comer@example.org"
Error: cannot contribute: this ceremony was closed by the beacon at step 3;
a beacon is final, so no further step can be appended.
```

- **A beacon closes the ceremony.** Nothing may follow it, and there is at most one.
  A transcript with a post-beacon step is rejected even when that step carries a
  valid proof of knowledge.
- **A beacon cannot be relabelled into a contributor.** The kind and provenance are
  bound into the proof of knowledge, so relabelling invalidates the step for anyone
  who does not know its delta ratio; and for the one party who does (a beacon scalar
  is public), the pre-committed beacon value above lets any verifier catch it. With
  no pre-commitment supplied, the relabelling is indistinguishable and the report
  says so rather than claiming a check it did not perform.

## The end-to-end check

`mirror-cli ceremony prove-check` verified the ceremony, generated a membership proof
under the ceremony-produced proving key (in process, pure Rust), and ran the **exact
on-chain `groth16-solana` verifier** the program runs over that proof against the
ceremony-exported verifying key:

```
PASS: the on-chain groth16-solana verifier accepts a proof made under the
      ceremony-produced proving key, checked against the ceremony-exported
      verifying key. The ceremony output is a working Groth16 key.
```

Independent cross-checks on the same proof:

```
$ snarkjs groth16 verify <ceremony vk> public.json proof.json
[INFO]  snarkJS: OK!

$ snarkjs groth16 verify circuits/artifacts/verification_key.json public.json proof.json
[ERROR] snarkJS: Invalid proof
```

The second line is the important one: the proof is rejected under the OLD dev
verifying key, so the check cannot have passed by accidentally exercising the old key.

Comparing the exported verifying key against the committed dev key field by field:

| field | same as dev key? |
| --- | --- |
| `vk_alpha_1` | yes |
| `vk_beta_2` | yes |
| `vk_gamma_2` | yes |
| `IC` (all entries) | yes |
| `vk_delta_2` | **no** |

Only `delta` moved. That is exactly what a phase-2 ceremony is defined to do.

## Second circuit, independent transcript

The transaction (JoinSplit) circuit was run as a separate ceremony over the same
public phase 1, and closed with the same published beacon value:

| item | value |
| --- | --- |
| r1cs sha256 | `908988ec0ee6626b7d8fd39892e12166b5ec75ef1a3a259b64bdc1a6c8990063` |
| initial key digest | `3f7eb98b3a72011d21e4af5b45eff1402007688c07770973a8dec4a6816e8beb` |
| steps | 2 entropy contributions + closing beacon |
| final key digest | `cf960b337d8650780749e6dceb7e9b8a325e4be4a1b5534b808503f8ed8fc337` |
| final ceremony hash | `ea5608fdab7820d9c17c4271fb1d93bae35e7da732c90acd75b4051d3d8a4cf7` |
| transcript file sha256 | `2c846e103be37a1490a3105e8f9e5d1b8bd431cc02ef2b2a444aef8f6e7b406a` |
| verify | `CEREMONY VERIFIED`, closed by beacon, 1 independent contributor (same-machine merge) |

`prove-check` deliberately refuses this ceremony: it builds a membership witness, and
constructing a full 2-in/2-out JoinSplit witness is out of its scope. That circuit's
ceremony is verified and exportable, but its end-to-end proof check is not automated.

## What a third party can check

The transcripts are committed; the proving keys are not (4.7 MB and 11 MB of
gitignored build artifact). So:

```sh
mirror-cli ceremony verify-transcript \
  --file docs/ceremony-run/membership-transcript.json \
  --beacon-source-text "mirror-pool demo beacon 2026-07-27" \
  --beacon-iterations-exp 16
```

reproduces, from the committed file alone: the whole hash chain and the published
ceremony hash, every Schnorr proof of knowledge at its own position and under its own
label, every `delta_g1`/`delta_g2` same-ratio pairing, the beacon step recomputed
point for point from the published source, the beacon-is-final rule, and the
contributor count of 1.

It does **not** reproduce the four key-level checks (initial-key binding, final-key
binding, untouched-part equality, `h_query`/`l_query` scaling), because those compare
against key files that are not published. The command prints
`TRANSCRIPT VERIFIED (no key files: the key-level checks did NOT run)` and lists what
it skipped. Those checks did run locally, in the `ceremony verify` output quoted
above, and they run in the test suite on synthetic keys - but for *this specific run*
they are not externally reproducible, and this document does not claim they are.

The committed transcripts are also checked by
`cargo test -p mirror-ceremony the_committed_demo_transcripts_verify`, which pins
their final ceremony hashes to the values published above, so the published evidence
cannot drift away from the code that produced it.

## Timings (optimized build, Apple silicon)

| operation | membership (11522 constraints) | transaction (27278 constraints) |
| --- | --- | --- |
| `ceremony start` (read zkey, write key) | 1.0 s | 1.9 s |
| `ceremony contribute` | 1.9 s | 4.2 s |
| `ceremony beacon` (`2^16` iterations) | 1.9 s | n/a |
| `ceremony verify` (whole chain) | 0.2 s | 0.4 s |
| `ceremony verify-transcript` (no key files) | 0.04 s | 0.03 s |
| `ceremony prove-check` (verify + prove + on-chain verify) | 0.6 s | n/a |

Key files are 4.7 MB (membership) and 11 MB (transaction). Transcripts are ~7 KB.

Build note, unrelated to the ceremony: on the toolchain used here (Rust 1.92 with
Apple's `ld`), a `--release` link of any binary that pulls in `solana-rpc-client`
fails during LTO with a bitcode-version mismatch inside
`spl-token-confidential-transfer-proof-*`. This affects `mirror-cli` and
`mirror-coordinator` equally and predates this work; `CARGO_PROFILE_RELEASE_LTO=false`
works around it, and the timings above were measured with that. Debug builds, and
every gate (`cargo check` / `fmt` / `clippy` / `test`), are unaffected.

## Reproduce

```sh
D=ceremony/membership
BEACON="mirror-pool demo beacon 2026-07-27"
mirror-cli ceremony inspect-ptau --ptau circuits/pot16_final.ptau
snarkjs groth16 setup circuits/membership.r1cs circuits/pot16_final.ptau \
  circuits/membership_0000.zkey
mirror-cli ceremony start --circuit membership --dir "$D" \
  --r1cs circuits/membership.r1cs --ptau circuits/pot16_final.ptau \
  --initial-zkey circuits/membership_0000.zkey
mirror-cli ceremony contribute --dir "$D" --id "alice@example.org" --entropy "<yours>"
mirror-cli ceremony contribute --dir "$D" --id "bob@example.net" --entropy "<yours>"
mirror-cli ceremony contribute --dir "$D" --id "carol@example.com" --entropy "<yours>"
mirror-cli ceremony beacon --dir "$D" --id coordinator \
  --source-text "$BEACON" --iterations-exp 16
mirror-cli ceremony verify --dir "$D" \
  --r1cs circuits/membership.r1cs --initial-zkey circuits/membership_0000.zkey \
  --beacon-source-text "$BEACON" --beacon-iterations-exp 16
mirror-cli ceremony prove-check --dir "$D" --out-dir /tmp/cproof
snarkjs groth16 verify /tmp/cproof/verification_key.json \
  /tmp/cproof/public.json /tmp/cproof/proof.json
```

The same flow also runs as a test:

```sh
MIRROR_PROVE_LIVE=1 cargo test -p mirror-cli -- --ignored ceremony_key
```

With `MIRROR_PROVE_LIVE=1` set, that test now FAILS if the circuit build artifacts
are missing, instead of returning early and reporting success. Without the flag it
skips, which is what CI does.

Your digests from step 0 onward will differ from the table above (different entropy);
the phase-1 digest, the r1cs digest and the initial-key digest will not.

---

# Trusted-setup ceremony - the DEPLOYED keys

The run above is a demonstration. The three below produced the verifying keys
that are **actually committed and deployed**: `circuits/artifacts/{vk,transaction_vk,association_vk}.rs`,
their vendored copies in `programs/mirror-pool/src/`, the three digests in
`programs/mirror-pool/src/vk_digest.rs`, and the registry accounts of the devnet
program `EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq`.

Each is a **1-independent-contributor** ceremony. None is a large ceremony and this
document does not present them as such; `docs/CEREMONY.md` section 10.4 states
exactly what one independent contributor does and does not buy. No dev-setup key
is deployed any more.

They differ in one respect that matters, and it is not smoothed over: the
transaction and association ceremonies closed on a beacon slot that was
**pre-committed in public before its value existed**, and the membership ceremony
did not.

## What they were

| item | membership | transaction | association |
| --- | --- | --- | --- |
| r1cs sha256 | `8ed37995...977bd0a2` | `908988ec...c8990063` | `a6c0e970...645297c6` |
| phase 1 | public perpetual powers-of-tau, sha256 `1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922`, 55 contributions, `2^16` slice of a `2^28` ceremony | same | same |
| initial phase-2 key | `8c6b6c48...51b15697` | `3f7eb98b...816e8beb` | `2bbcc8ec...add5bf6e` |
| steps | 2 (1 secret-entropy contribution, 1 beacon) | 2 | 2 |
| independent contributors | **1** | **1** | **1** |
| beacon slot | `435825712` | `435846661` | `435846661` |
| beacon pre-committed? | **no** - slot chosen after the contribution | **yes** | **yes** |
| final key digest | `f9d8f7f6423af7795efb379bd9686aaab2a7e5c7614e460247afb080e542c485` | `63f1dc3c424587e40a89670f6d0d481acc311b791155e3e37f353fc89cd0f87d` | `8d76e73f5e191cf577eb8fa971098410f772e19111a00004f52ab6411b9d0fa6` |
| final transcript hash | `884c88601173b1f08bd2e26626b0fe4c553dedffe707b2387db754417a9cdd05` | `6d0449341db0744509782a2249e3fd8182aa4bc228f3b2774312fefd81bbaa80` | `5ef80404f6136cd2a9f843c57fe928c87200142f1a7d4c0ce181ff26f0808e1d` |
| published transcript | `docs/ceremony-run/membership-deployed-transcript.json` | `docs/ceremony-run/transaction-deployed-transcript.json` | `docs/ceremony-run/association-deployed-transcript.json` |
| canonical vk | 769 bytes, sha256 `be5f776d...043e4c76` | 961 bytes, sha256 `4b542099...b38e28c1` | 833 bytes, sha256 `90d13582...062832ee` |

The beacons, as published Solana mainnet-beta blocks:

```text
membership   slot 435825712  blockhash 9Gth2wVt86WhS1fh5FS7FihGvxyaesunW28M3zjD46Eu
transaction  slot 435846661  blockhash 67Y5hxUdXtxczqCcFnQkcqmPXJUDbSq7yKFGqhUzWLgH
association  slot 435846661  blockhash 67Y5hxUdXtxczqCcFnQkcqmPXJUDbSq7yKFGqhUzWLgH

source string  "solana-mainnet-beta slot <SLOT> blockhash <BLOCKHASH>"
iterations     2^20 SHA-256 iterations
```

## The pre-commitment, and why it is the interesting part

`docs/ceremony-run/BEACON-PRECOMMITMENT.md` was written and pushed while slot
`435846661` was still roughly 25 minutes in the future, at slot `435842661`. It
names the slot and fixes the exact source string. Nobody, the operator included,
could predict that block's hash when the file was written.

Slot `435846661` **was produced** (parent `435846660`, block height `413905124`),
so no substitution was needed and the commitment was honoured exactly as
written. Anyone can fetch the block, rebuild the source string, and recompute the
beacon scalar:

```sh
solana block 435846661 --url mainnet-beta   # blockhash 67Y5hxUdXtxczqCcFnQkcqmPXJUDbSq7yKFGqhUzWLgH
```

`ceremony verify` reports `CEREMONY VERIFIED`, closed by beacon, and - when that
value is supplied - `beacon pre-commitment: checked against the value you
supplied`, for all three. For membership that check still only proves the last
step is the announced beacon rather than a relabelled secret contribution; it
cannot rule out that the operator shopped for a favourable slot, because the slot
was named afterwards. For transaction and association it can, because the slot was
named first. That is the whole difference, and it is why the pre-commitment file
was written before the ceremonies rather than alongside them.

## Redeploy to devnet

The program was upgraded **in place**, so the program id and every explorer link in
this document survive:

```text
program id         EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq
upgrade signature  27Hg4jV8W4UeCY9RX9kpNfwJoMVz5BE4qRMpV9AqwN1Z3Y1bygy9vMwszM4E4vhZs69otSHg3Dwrn61DDTGfVLbF
slot               479622920
upgrade authority  B2xLRxRKYTqusezsqhNZBPneJHsSCZn5L5ik8DqJQDGR
```

- Upgrade transaction: https://explorer.solana.com/tx/27Hg4jV8W4UeCY9RX9kpNfwJoMVz5BE4qRMpV9AqwN1Z3Y1bygy9vMwszM4E4vhZs69otSHg3Dwrn61DDTGfVLbF?cluster=devnet
- Program: https://explorer.solana.com/address/EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq?cluster=devnet

The on-chain bytecode was dumped back and compared against the local build:

```text
on-chain dump      127680 bytes
local .so          127680 bytes
identical          yes (byte-for-byte, including the trailing zero padding)
sha256             5b8cfdc0112b084ce3a5189333b719388a8b29a3f6300a7fed531ba4c3fa7d93
```

```sh
solana program dump EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq /tmp/onchain.so --url devnet
cmp /tmp/onchain.so programs/mirror-pool/target/deploy/mirror_pool.so && echo IDENTICAL
```

## Verifying-key registry state on devnet

The registry is write-once per circuit, and all three now hold a ceremony key:

```text
membership   6fkK14YXovKkJQ7z2Df7sBeCGPEnRK2XGBrRkMJJbRYg   published, sha256 be5f776d...043e4c76
transaction  BD1cm4jqbDHxgWX7ZfLmFaWWc1wSJFr5h68YesrkuCfW   published, sha256 4b542099...b38e28c1
association  3EyfUQZFSEz1VcTkCK3EsUV5uE8XqyCBmCQHETqjhWVn   published, sha256 90d13582...062832ee
```

None of them could have held anything else: `InitVk` hashes the bytes it is given
and refuses everything but the digest the bytecode pins, and there is no update
instruction. Their `InitVk` transactions are linked in the deployment table near
the top of this file.

## What a third party can check, and what they cannot

Reproducible from this repository and a devnet RPC:

```sh
# 1. the three deployed transcripts, with no key files, beacon values supplied
make ceremony-verify-run

# 2. each committed key hashes to the constant the program pins
for c in membership transaction association; do
  mirror-cli init-vk --circuit $c --dry-run \
    --program-id EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq \
    --payer <any keypair> --rpc-url https://api.devnet.solana.com
done
# -> be5f776d2a4ba83655c50a9ecf47192cd3aa74075cd9e3d8a62bd99e043e4c76
#    4b542099cea5bd4dfdfd6f9d5d649bc23acd9aab35d8f3ac1a984e13b38e28c1
#    90d13582aba26708672b3f118dea345c9636534b1b9de3fd7fce4708062832ee

# 3. the deployed bytecode is the bytecode in this tree
solana program dump EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq /tmp/onchain.so --url devnet
cmp /tmp/onchain.so programs/mirror-pool/target/deploy/mirror_pool.so

# 4. each vendored key equals the ceremony-exported artifact (comments aside:
#    the vendored copy carries an extra PROVENANCE header)
strip() { grep -v '^//' "$1" | awk 'NF || seen { seen = 1; print }'; }
for c in vk transaction_vk association_vk; do
  diff <(strip "programs/mirror-pool/src/$c.rs") <(strip "circuits/artifacts/$c.rs")
done

# 5. the beacon the two pre-committed ceremonies closed on
solana block 435846661 --url mainnet-beta
```

Not reproducible by a third party: the key-level ceremony checks (initial-key
binding, final-key binding, untouched-part equality, query scaling) and
`prove-check`, all of which need the multi-megabyte `.mpk` proving keys. Those are
gitignored build artifacts and are not published, exactly as for the demonstration
run. This document does not claim otherwise.

---

> **The funding-round evidence below is local-validator only, and CURRENT.** It
> was re-run after the ceremony-key upgrade, against a fresh local deployment of
> the identical `mirror_pool.so` (sha256
> `5b8cfdc0112b084ce3a5189333b719388a8b29a3f6300a7fed531ba4c3fa7d93`), so it
> describes the same bytecode as the devnet sections above. What it is NOT is a
> public-cluster record: the signatures are local-validator signatures and resolve
> on no explorer. `mirror-soak-funding` publishes the JoinSplit verifying key
> through `init-vk` before it releases anything, and proves under the phase-2
> ceremony key.

<!-- funding-round-soak:begin -->
## Funding-round soak

This section documents an automated end-to-end run of `mirror-soak-funding` against a
LIVE local Surfpool validator (a local mainnet mirror at `http://127.0.0.1:8899`), treated as mainnet and
run honestly. It exercises the FUNDING-PROVENANCE path through the shipped components:
`mirror-cli shield | scan | fund-commit` on the participant side, and
`mirror_coordinator::FundingService` + `DirectoryIntake` on the coordinator side, which
polls the real chain slot, ingests the emitted requests, batches them into slot rounds,
and releases each round through the gasless relay. The signatures below are
local-validator signatures, reproducible by re-running the soak against a fresh Surfpool,
not lookups on a public explorer.

- generated: unix 1785288083
- program id (fresh deploy): `G3BZDddarBdm1rGDE9XBMuSUXYiLBPkjVpgcujjwvSf5`
- funding ValuePool: `CKzjvGkSZJrKw4fs8F88B8iZP2j4nCj1q96Mz3427deA` (authority / relay `5AFx6bn38pJiv3GWwLG7TSd18DbEfQZ7Yaei8eFAThiZ`), vault `DwY3Bpbw4dFdDvkfkRxCttLvvaTj3iJ37MW1yHxfAtuJ`
- behavioral Pool: `BHLqreMaQLzBdJgG9pSER5wv1KTEMGU2MsMvjKapKTgq`
- denomination: 100000000 lamports (every shield and every funding withdrawal moves exactly this)
- round: 12 slots, `min_round_size` 4, 4 participants; the released round was 36320433 at slot 435845208

### What was exercised

1. **Setup** - a denominated funding `ValuePool` plus the behavioral `Pool` a funded
   commit wallet participates in.
2. **Shield** - every participant shields exactly the denomination from their OWN main
   wallet, then `scan`s the on-chain `enc` blobs to recover a spendable note.
3. **Request** - `fund-commit` mints a FRESH commit-wallet keypair and emits its
   relay-only-signed unshield into the coordinator's inbox directory.
4. **Thin round** - a round below `min_round_size` rolls forward, and nothing reaches
   the chain while it is thin.
5. **Release** - the merged round releases at its boundary; each fresh commit wallet is
   credited exactly the denomination and the vault is debited by exactly the sum.
6. **Provenance** - every funding transaction carries exactly one signature (the
   relay's), mentions no participant main wallet, and each fresh commit wallet's ONLY
   inbound transfer across its entire on-chain history is from the pool vault.
7. **Participation** - a funded commit wallet then commits to the behavioral pool,
   paying its own fee out of the pool-funded balance.
8. **Adversarial** - a wrong-amount request is refused client-side by the CLI and
   coordinator-side at the intake, and a live mid-round submit failure re-queues the
   remainder instead of dropping it.

What this does NOT claim: the shield leg is still the participant's own transaction from
their own wallet, and both boundary crossings expose an amount and a slot. The funding
edge is not erased, it is turned into a matching problem; the residual is measured in
`docs/EFFECTIVE_K.md`, not assumed away.

### On-chain assertions

27/27 assertions passed.

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | G3BZDddarBdm1rGDE9XBMuSUXYiLBPkjVpgcujjwvSf5 |
| PASS | JoinSplit verifying key published into its write-once registry PDA | init_vk: 58ZuzJz8jV6CK1JsdFAipJiZ2tVDjaxy4VkDNtv66grQfxjWELwNptBSUzferirt8DMCDwqmdfpygv5DdnFQ6M11 |
| PASS | denominated funding ValuePool initialized (uniform amount enforced on-chain) | vpool=CKzjvGkSZJrKw4fs8F88B8iZP2j4nCj1q96Mz3427deA vault=DwY3Bpbw4dFdDvkfkRxCttLvvaTj3iJ37MW1yHxfAtuJ denomination=Some(100000000) |
| PASS | funding-pool ALT created + extended (keeps a release inside one packet) | alt=3VVJ6q4YSB8LiuJcwKogbVKCZdfuxHwuCUQbChBDq5tg (5 shared accounts) |
| PASS | behavioral Pool initialized (the pool a funded commit wallet participates in) | pool=BHLqreMaQLzBdJgG9pSER5wv1KTEMGU2MsMvjKapKTgq epoch_slots=60 k_floor=2 |
| PASS | every participant shielded EXACTLY the denomination (uniform deposits) | vault credited 400000000 lamports = 4 x 100000000 |
| PASS | every participant recovered a SPENDABLE note by scanning | 4 notes recovered from the on-chain enc blobs |
| PASS | fund-commit minted a FRESH commit wallet per participant (all distinct, none a main wallet) | 4 distinct commit wallets |
| PASS | every fresh commit wallet is UNFUNDED before the round releases | no commit wallet had any lamports at request time |
| PASS | the coordinator INGESTED the fund-commit emits (the shipped intake path) | 3 request(s) batched into round 36320432 at slot 435845187 |
| PASS | a round below min_round_size ROLLS FORWARD instead of releasing | round 36320432 held 3 < min_round_size 4 and moved to round 36320433 |
| PASS | a thin round reaches the chain NOT AT ALL (every commit wallet still unfunded) | all 4 commit wallets still at 0 lamports |
| PASS | the merged round RELEASED every batched withdrawal at its boundary | round 36320433 released 4 withdrawals at slot 435845208 |
| PASS | every fresh commit wallet is credited EXACTLY the denomination | 4 wallets each credited 100000000 lamports |
| PASS | the pool vault was debited by exactly the sum released | vault debited 400000000 lamports (= 4 x 100000000) |
| PASS | every funding transaction carries EXACTLY ONE signature | signature counts: [1, 1, 1, 1] |
| PASS | that one signature is the RELAY's (fee payer at account key 0) | relay 5AFx6bn38pJiv3GWwLG7TSd18DbEfQZ7Yaei8eFAThiZ |
| PASS | no funding transaction mentions ANY participant main wallet | 4 main wallets checked against 4 funding transactions |
| PASS | each fresh commit wallet's ONLY inbound transfer is from the pool vault | wallet JCgpGJvBCc5n72DGBBfo4fj6LBfXtcqVa3miio2XbdtX: 1 transaction(s) in its entire history, 1 inbound, the only credit is 100000000 lamports debited from the vault DwY3Bpbw4dFdDvkfkRxCttLvvaTj3iJ37MW1yHxfAtuJ |
| PASS | the release order within a round is ARRIVAL-INDEPENDENT (same round, reversed arrival, identical release sequence) | arrival-order run ["9UB14F", "JCgpGJ", "H9y87L", "NX8yCd"] == reversed-arrival run ["9UB14F", "JCgpGJ", "H9y87L", "NX8yCd"] |
| PASS | the on-chain submission sequence IS the release order, not the arrival order | released ["9UB14F", "JCgpGJ", "H9y87L", "NX8yCd"] while participants arrived ["JCgpGJ", "H9y87L", "9UB14F", "NX8yCd"] |
| PASS | the funded commit wallet COMMITS to the behavioral pool, paying its own fee | epoch 7264087 commit_count=1 and the wallet paid 1118600 lamports out of its pool-funded balance |
| PASS | CLI fail-fast: a wrong-amount funding request is refused client-side | Error: this value pool is denominated at 100000000 lamports; --amount 100000001 would be rejected on-chain (DenominationMismatch) and a distinctive amount re-links the funder to the funded wallet anyway  |
| PASS | coordinator refuses an off-denomination request at the intake (no relay signature burned) | doctored-request.json: funding withdrawal of 100000001 does not match the pool denomination 100000000; a distinctive amount re-links the funder to the fundee |
| PASS | the refused request was quarantined, not batched | the doctored emit is in rejected/ and no round holds it |
| PASS | a mid-round submit failure RE-QUEUES the remainder instead of dropping it | the submit at release position 1 failed (submitting funding withdrawal in round 36320437 (index 3): send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x3: 7 log messages: Program ComputeBud), and 3 of 4 withdrawals moved into round 36320438 |
| PASS | the withdrawal released BEFORE the failure still landed (partial release, honestly reported) | release position 0 (ZWha4nbbechNhEdAv6KRDwUcn1r6ZZuuh2DphCu6nnx) is funded; the poisoned request at position 1 belonged to participant 3 (wallet CT2iywfMJgqjUqGdZ8iFuwdEb4aDfDMSuey5EaHXBHpR) |

### Honest notes from this run

- the re-queued remainder keeps the FAILING request with it, so the same request fails again in the next round it lands in, releasing only the withdrawals ordered before it. The good requests still drain (the failing one drifts through the deterministic order), but a permanently-invalid request degrades round throughput until an operator removes it. FundingRounds has no quarantine policy for that today.

### Captured transaction signatures

| step | signature |
| --- | --- |
| init_vk_transaction | `58ZuzJz8jV6CK1JsdFAipJiZ2tVDjaxy4VkDNtv66grQfxjWELwNptBSUzferirt8DMCDwqmdfpygv5DdnFQ6M11` |
| init_value_pool_funding | `36Qq5EnTjx8KouV5XBrm2o2NZ5exDjPkJrkubUDRwe4mKmzmawJjwXYBZbL9Eq7QZe5PEpJZYzGamCQPtb5Frg3M` |
| init_pool_behavioral | `27rgr9Mzy6Z1XMqnTj9vCmmAd7JtP5VH1eFYrz4zDsxDvR11JMdSa4H7vMn4CMX3LUkEoa1H6AZ4dkauXL2MjDvZ` |
| shield_0 | `5kXyMLoWEiBd7LgeGnyHo71Zu33WtQrbPNjru7vKiC6Eq98FCsciUcgWv4995T72GMFfNp7rM3k15vpCc3GDcGBN` |
| shield_1 | `3x3UxehonHHj4XCQSofrjCXnYasHRK59MamKtJGFZRzHrEHbH9TXX41LJ4y7p8AowAqTwUwt3DChnrxczkpbJ8WM` |
| shield_2 | `4m2p6rBnWQbsNh2Qy7HiujcdueBS91haQWpLpGYXmwbeF1h5Q5N8hbwarxRsogBNz3KeDGZv6YR9sUeGg76mPyg2` |
| shield_3 | `51QDB58RmQYLe22Vb7pwvcMFbibwYFmaWtJo3fhRUKzAAm1L8qnEcrf6zmfSBbV5r3h5jMwhVqPPuf8Uks2DJxQL` |
| funding_release_0 | `3oacYzSaQtXBtafULok55K8dwQd4ozHYh2xANkYco1PEqj5cwzP6hg8XsW7j5xwic9m4XR2JceKwjVHraiFnsNga` |
| funding_release_1 | `2oSc77Fy36vLRq8auQsg2hxubhar6gcYwNbP27YWWc3yj69Xvn5EReBCJVW9mfjYxGEm2yHVNjZtefKzDTQcA2G2` |
| funding_release_2 | `5fCMKCSFrSFdoNa88aGTYsWMUpxRbNBajbQjJcvzs4fHTXp8C4M1h6MLhAKxKJMqDB4qR62nh4uuQW8BH5kHH4rV` |
| funding_release_3 | `2MePWFUWkFC8Zt3hWWoFufNfqNEEUfVZwrep9VPAkvgaGCKNrGaKXbcCtpCvVMcUgG66RbuU8MsvzFedCnMmH2BR` |
| commit_from_funded_wallet | `2bY65muzN41DTZYD3mrVogvXuZ6SPWo4DDFqyh3zxeYmpCAspkZPuvV472rpgVJSTfw3iT4uJTgoGAo1ukGZpdir` |
| out_of_band_spend | `TWZuY3j53sYbEGFR75Mdj7GNkqHeD7qSqy9Y7n5qRhbcNyLiaJ9oEmvy84RnxyERuo6HprJEAEGHen544B8EUFS` |

### Compute units (the released funding withdrawals)

| signature | compute units |
| --- | --- |
| `3oacYzSaQtXBtafULok55K8dwQd4ozHYh2xANkYco1PEqj5cwzP6hg8XsW7j5xwic9m4XR2JceKwjVHraiFnsNga` | 200073 |
| `2oSc77Fy36vLRq8auQsg2hxubhar6gcYwNbP27YWWc3yj69Xvn5EReBCJVW9mfjYxGEm2yHVNjZtefKzDTQcA2G2` | 199379 |
| `5fCMKCSFrSFdoNa88aGTYsWMUpxRbNBajbQjJcvzs4fHTXp8C4M1h6MLhAKxKJMqDB4qR62nh4uuQW8BH5kHH4rV` | 200929 |
| `2MePWFUWkFC8Zt3hWWoFufNfqNEEUfVZwrep9VPAkvgaGCKNrGaKXbcCtpCvVMcUgG66RbuU8MsvzFedCnMmH2BR` | 205530 |

### Reproduce

With a local Surfpool running at `http://127.0.0.1:8899` (treated as mainnet). That endpoint is whatever
`--rpc-url` was given for this run; `surfpool start --no-tui` listens on port 8899 by
default, and any other port here simply means the run was pointed at one.

```sh
# 1. build the on-chain program + host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program under a FRESH program id
solana-keygen new -o .soak/keys/funding-program.json
solana program deploy \
  --url http://127.0.0.1:8899 \
  --program-id .soak/keys/funding-program.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. build the transaction-circuit artifacts (bash circuits/build_transaction.sh)

# 4. run the funding-round soak
cargo run -p mirror-soak --bin mirror-soak-funding -- \
  --rpc-url http://127.0.0.1:8899 \
  --program-id G3BZDddarBdm1rGDE9XBMuSUXYiLBPkjVpgcujjwvSf5
```

Every run creates a fresh pool, fresh main wallets, and fresh commit wallets, so the run
is self-contained and repeatable; the signatures above are from this run.
