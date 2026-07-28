# mirror-pool - proof of operation

This file has two independent, honestly-labeled proofs of the same program:
a **public Solana devnet deployment** (top, browser-verifiable on the Solana
Explorer) and the original **local Surfpool mainnet-mirror run** (bottom).

> **The deployed program matches this source tree again, but the tables below do
> NOT belong to that bytecode.** The devnet program id below has since been
> **upgraded in place** to the current build (signature
> `58gKGUdvKowyv4phxNUxKxiPbbnWNps9SKhxVkLWt7V8Q7DQLhrTuH2UWhUPtDzmeSPTEBExzXYeGVeYDuGFWHm`,
> slot `479600717`; the dumped on-chain bytes are byte-for-byte the locally built
> `mirror_pool.so`, sha256
> `6b026cf95e7f76d8a45c248004f98e2f647e7fc806203e1785bdeddcbea4f466`). That build
> carries three things the earlier one did not: the write-once digest-pinned
> verifying-key registry with its `InitVk` instruction
> ([`VK_REGISTRY.md`](VK_REGISTRY.md)), the ZK-escrow domain-separation fix, and
> the phase-2 **ceremony** membership key.
>
> Every run recorded in this file - behavioral 17/17, confidential 25/25, funding
> 25/25 - was captured against the EARLIER bytecode at this same address and is
> left exactly as captured. It is still valid evidence for what it was evidence of
> (the pool's behavioral and confidential mechanics on a live public cluster); it
> is NOT evidence about the registry, the escrow fix, or the ceremony key, and the
> instruction shapes differ (the settle instructions now take one more account,
> and `InitPool` takes a 31-byte body where the old one took 23). **The soaks have
> not been re-run against devnet since the upgrade.** The behavioral soak WAS
> re-run end to end against a local Surfpool on a fresh deployment of the
> registry bytecode and passed 18/18 (the extra assertion being the verifying-key
> publication); those local-validator signatures are recorded in
> [`VK_REGISTRY.md`](VK_REGISTRY.md) section 8 and deliberately NOT merged into
> the tables below.

> **The ZK escrow fix, for the record.** The crowd `Commit` leaf is
> domain-separated from the ZK deposit leaf by the program
> (`crowd_leaf = Poseidon(CROWD_LEAF_DOMAIN, commitment)`), and a pool fixes one
> `zk_denomination` at init that `CommitDeposit`, `SettleZk` and
> `SettleZkAssociated` all require. Together they close a fund-theft hole in which
> a fee-only crowd commit could spend a depositor's escrow
> ([`THREAT_MODEL.md`](THREAT_MODEL.md) section 4). The bytecode that produced the
> tables below had NEITHER; the bytecode deployed at that address today has both.
> The fix's evidence remains the mollusk suite against the compiled SBF program,
> including the inverted attack test
> `settle_zk_rejects_a_fee_only_crowd_leaf_spending_a_depositors_escrow`, not a
> public-cluster run.

> **Re-running the soaks on a public cluster is now possible, and has not been
> done.** The earlier blocker was funding: the upgrade needed roughly 0.83 SOL of
> rent against a funder holding 0.4498 SOL, and the devnet faucet was refusing the
> address. The funder has since been topped up and the upgrade landed, so all
> three soak drivers - each of which publishes its verifying key through `init-vk`
> before it settles - could now run against devnet. They have not been re-run, so
> the public-cluster tables below stay exactly as captured. One public-cluster
> measurement made against the older bytecode, a multi-hour sustained crowd-path
> run with its topology delta stated, is recorded in [`DEVNET.md`](DEVNET.md).

> **These are records of runs, not descriptions of the current tree.** Both runs
> predate the move to in-process pure-Rust Groth16 proving, so several assertion
> rows below say the proof was generated and verified by `snarkjs`. That is what
> happened in those runs and the rows are left as they were recorded. The
> participant CLI now proves in-process via `ark-circom`/`ark-groth16` with no
> Node process, and `--use-snarkjs` is a legacy fallback; `circom`/`snarkjs` are
> still needed at BUILD time to produce the `.wasm`/`.r1cs`/`.zkey` artifacts,
> and `snarkjs groth16 setup` is still the ceremony's phase-2 starting point.
> Nothing else about the runs changed: every signature, compute-unit figure and
> on-chain assertion below is exactly as captured.

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
- deploy/upgrade transaction: https://explorer.solana.com/tx/q87TXz1ftYz8eiDUNa5o9PxVQeie1feikDCH3hBeFg92bhYEGrYDTYUpUAMforuLUatifY2fLU89R92sRnwok6f?cluster=devnet
- cluster: devnet (`https://api.devnet.solana.com`)
- driving commitment: `confirmed` for submission; every captured signature
  below was then re-confirmed at the `finalized` commitment before listing.

The program id above is a fresh, bounty-dedicated keypair (kept gitignored
under `.soak/keys/`). It was deployed and then upgraded in place; the SHA-256 of
the on-chain program bytes equals the SHA-256 of the locally built
`mirror_pool.so`, so the deployed program is exactly the source in this repo.
Both suites below ran against that same address, but against the **earlier**
bytecode - see the notes at the top of this file and the redeploy record in
"Trusted-setup ceremony - the DEPLOYED membership key" below.

## Behavioral soak - crowd + ZK settlement (devnet)

Fresh pool per run (fresh relay authority). Config: epoch_slots=128, k_floor=3, entry_fee=1000000 lamports, reward_bps=2500.

- pool PDA: `5ZqjRqhrYHradrMKih8YnejvfwsSLShYbnqXsLqUYWT7` (authority / relay `6FzpfHXu5SKNCpHummh6ZujrRpC6icNxzdtZuYyeew5N`)
- pool (Explorer): https://explorer.solana.com/address/5ZqjRqhrYHradrMKih8YnejvfwsSLShYbnqXsLqUYWT7?cluster=devnet
- ZK opt-in escrow amount: 50000000 lamports
- reward pool accrued at end of run: 1750000 lamports
- total leaves appended: 7

What was exercised: 4 participants commit the SAME PlainTransfer action into
one shared epoch, settled by ONE atomic gasless transaction (ComputeBudget +
SettleEpoch + 4 identical transfers, over a pool ALT); a ZK opt-in escrow is
settled by a snarkjs-verified Groth16 SettleZk to a fresh recipient; and the
adversarial cases (under-floor no-settle, duplicate nullifier, re-settle,
mismatched-recipient, replay) all fail closed on-chain.

### On-chain assertions (17/17)

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq |
| PASS | pool initialized with fixed config | version=1 epoch_slots=128 k_floor=3 entry_fee=1000000 authority=relay |
| PASS | pool ALT created + extended | alt=EXxNZeipF8QzJu8VEzmvX8Dp6xmGXLFzAEREPiXMizqt (6 shared accounts) |
| PASS | 4 commits batched into one shared epoch | epoch_id=3739202 commit_count=4 settled=false |
| PASS | duplicate crowd nullifier rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x3; 5 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program 1 |
| PASS | crowd epoch marked settled on-chain | epoch_id=3739202 settled=true |
| PASS | 4 nullifier PDAs created (anti-replay) | 4/4 nullifier PDAs exist and are program-owned |
| PASS | 4 identical transfers executed atomically | sink credited 40000000 lamports (= 4 x 10000000 bucket) |
| PASS | re-settle of a settled epoch rejected (EpochAlreadySettled) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x6; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |
| PASS | under-floor epoch rejected on-chain (BelowKFloor) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x2; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |
| PASS | under-floor epoch rolled forward off-chain (coordinator) | coordinator.on_slot returned RolledForward (real_k < k_floor) |
| PASS | Groth16 membership proof generated + verified (snarkjs) | mirror-cli prove produced a snarkjs-verified SettleZk |
| PASS | SettleZk authority == pool relay | authority=6FzpfHXu5SKNCpHummh6ZujrRpC6icNxzdtZuYyeew5N |
| PASS | ZK settle to mismatched recipient rejected (ActionHashMismatch) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0xe; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |
| PASS | escrow landed at the FRESH recipient | recipient credited 50000000 lamports (= escrow 50000000) |
| PASS | ZK nullifier PDA created (anti-replay) | nullifier PDA 3QaTuACW2EESAfRG6icWCGEY7MJh4qPu33bo6rcPs4pW exists + program-owned |
| PASS | ZK replay rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 0: custom program error: 0x3; 3 log messages:   Program EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq invoke [1]   Program E |

### Finalized transaction signatures + compute units

| flow | signature (Explorer) | commitment | CU consumed |
| --- | --- | --- | --- |
| init_pool | [`38rNeKerPRcFxvBzRgGh3xZjXEgDUwi7vhjfGrYnUKbPcLRFbK7Q3wGyditkZyBF2Xg2pJ8LstYXAWGGfnR4KkfX`](https://explorer.solana.com/tx/38rNeKerPRcFxvBzRgGh3xZjXEgDUwi7vhjfGrYnUKbPcLRFbK7Q3wGyditkZyBF2Xg2pJ8LstYXAWGGfnR4KkfX?cluster=devnet) | Finalized | 21766 |
| crowd_commit_0 | [`4dzqpL2Mep5RNnbsLKsEgoBo7sx87F8pzWUGstLn9h4WjJ4QQnn9PAhRUDZVoYhU5VnXH8aPq9CSxAPTi2dxAaKy`](https://explorer.solana.com/tx/4dzqpL2Mep5RNnbsLKsEgoBo7sx87F8pzWUGstLn9h4WjJ4QQnn9PAhRUDZVoYhU5VnXH8aPq9CSxAPTi2dxAaKy?cluster=devnet) | Finalized | 41006 |
| crowd_commit_1 | [`Q4HRHLqvw6rC9CK7UdybVs1Q2RZLTNLvSeh9Ao7nZkLX18EWfYwYy1q1gmC48DtEQUEBoKKuD2sV49e6zovfJ4y`](https://explorer.solana.com/tx/Q4HRHLqvw6rC9CK7UdybVs1Q2RZLTNLvSeh9Ao7nZkLX18EWfYwYy1q1gmC48DtEQUEBoKKuD2sV49e6zovfJ4y?cluster=devnet) | Finalized | 39654 |
| crowd_commit_2 | [`4imuaAxEK66RxcamUSKBdxDEQjPCV11EuK8jVb9nfDJrxPNZXMCxaryfqfV2SaRn645jNCghUpNgGm3BcHZtQKdA`](https://explorer.solana.com/tx/4imuaAxEK66RxcamUSKBdxDEQjPCV11EuK8jVb9nfDJrxPNZXMCxaryfqfV2SaRn645jNCghUpNgGm3BcHZtQKdA?cluster=devnet) | Finalized | 39654 |
| crowd_commit_3 | [`3ZjS1ZbVv6fwJdpLvvZoEw13ap1jysUu8hyGyv6FE4nAbjTdvnAbL3vq5T5CnMjwcBYuXjGb6cYCJELmgviRVs8m`](https://explorer.solana.com/tx/3ZjS1ZbVv6fwJdpLvvZoEw13ap1jysUu8hyGyv6FE4nAbjTdvnAbL3vq5T5CnMjwcBYuXjGb6cYCJELmgviRVs8m?cluster=devnet) | Finalized | 39647 |
| underfloor_commit_0 | [`4Pv116kNm8wucjvcnikRKFGFnvJGVkYUvtnJ2TrKE3PfngRgke5Rn9kXqYNfqL7ZiSxGe8tNfzcRvKumfcAhurr5`](https://explorer.solana.com/tx/4Pv116kNm8wucjvcnikRKFGFnvJGVkYUvtnJ2TrKE3PfngRgke5Rn9kXqYNfqL7ZiSxGe8tNfzcRvKumfcAhurr5?cluster=devnet) | Finalized | 39499 |
| underfloor_commit_1 | [`3uyHnhXYNR18deP3YZPQGorq2sPDT6XxUWxFKsrA5sXQDPsQYFNRf5jhzqJjutwiuCue7onqbNzb8WUx3sC2rims`](https://explorer.solana.com/tx/3uyHnhXYNR18deP3YZPQGorq2sPDT6XxUWxFKsrA5sXQDPsQYFNRf5jhzqJjutwiuCue7onqbNzb8WUx3sC2rims?cluster=devnet) | Finalized | 38147 |
| crowd_settle | [`4tcgNnhbZe7YKM26F6SnXW1WctASqVEqQ9W4v4NQ85fDfkYe3eq7YqCr4n7bEogm7U5By17Lkc5Tqa7jmZx693NB`](https://explorer.solana.com/tx/4tcgNnhbZe7YKM26F6SnXW1WctASqVEqQ9W4v4NQ85fDfkYe3eq7YqCr4n7bEogm7U5By17Lkc5Tqa7jmZx693NB?cluster=devnet) | Finalized | 21111 |
| zk_deposit_commit | [`5sv5hVisBMtRCD4EeopUiQNyATAJXBNY3WPAtU7ERpRHgXmChJTyaz54QqThDknvd5EYkbVhbMtPFad7QEr744C`](https://explorer.solana.com/tx/5sv5hVisBMtRCD4EeopUiQNyATAJXBNY3WPAtU7ERpRHgXmChJTyaz54QqThDknvd5EYkbVhbMtPFad7QEr744C?cluster=devnet) | Finalized | 42447 |
| zk_settle | [`4t7hLjFQh2ZyfqXQd7SZAHUw1A5nnzDjdAKRtMj9MKDeCr3Twx7twLgtAa6oQmzAZSFsHYEGKcwFwMyuyessThto`](https://explorer.solana.com/tx/4t7hLjFQh2ZyfqXQd7SZAHUw1A5nnzDjdAKRtMj9MKDeCr3Twx7twLgtAa6oQmzAZSFsHYEGKcwFwMyuyessThto?cluster=devnet) | Finalized | 102115 |

## Confidential-value soak - shield / transfer / unshield (devnet)

Fresh pools per run. The 2-in/2-out JoinSplit `Transact` layer, driven by the
participant CLI and the gasless coordinator. (This run predates the move to
in-process pure-Rust proving, so the CLI proved with snarkjs here; it now proves
with `ark-circom`/`ark-groth16` by default and `--use-snarkjs` is the legacy
fallback.) A transfer is signed ONLY by the relay (hides WHO for that transfer)
and carries `publicAmount == 0` (hides HOW MUCH).

- main ValuePool: `3Eq5uznQjqLVVzwu973aYUXeGVsJskhhVWqxrVVzCFY4` (authority / relay `hfQPKv4EDrUNeEqQjWVC1EKRVaSgFeVRkrkRkCJPG4j`), vault `6S8PHSZ9g9Xd5ea6Vz4iPEa4J59i9hVMGfhUumETg3D2`
- main pool (Explorer): https://explorer.solana.com/address/3Eq5uznQjqLVVzwu973aYUXeGVsJskhhVWqxrVVzCFY4?cluster=devnet
- fixed-denomination ValuePool: `GPqqrTbmyJhskE55Tcy5ZzaRg5UbuA7QWYosQKNgLAi6` (denomination 10000000 lamports)
- relay fee bound into ext-data: 5000 lamports
- amounts: shield 50000000 lamports, hidden transfer 20000000 lamports, withdraw 20000000 lamports

### On-chain assertions (25/25)

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq |
| PASS | main ValuePool initialized (authority=relay, fee set, no denom) | vpool=3Eq5uznQjqLVVzwu973aYUXeGVsJskhhVWqxrVVzCFY4 vault=6S8PHSZ9g9Xd5ea6Vz4iPEa4J59i9hVMGfhUumETg3D2 fee=5000 denom=None cc=0 |
| PASS | fixed-denom ValuePool initialized (denomination pinned) | vpool=GPqqrTbmyJhskE55Tcy5ZzaRg5UbuA7QWYosQKNgLAi6 vault=8TmSateSoFfSDLsR4EhAHn2gue757z5CkX9ZK6PhUvxk denom=Some(10000000) |
| PASS | shield proof generated + verified (snarkjs) and emitted | mirror-cli shield produced a snarkjs-verified Transact |
| PASS | vault credited by the shielded deposit amount | vault delta 50000000 lamports (= shield 50000000) |
| PASS | value root advanced + both output commitments inserted | commitment_count 0->2, root changed |
| PASS | both input nullifier PDAs created (anti-replay) | nf0=Ho6imx4KE5oB1obLgcpWXC77MLSKrY2iKLumrHUSsfHJ nf1=A8TF6r3n5kkzkMsSD9PRFCDAYntiQUsLcyQznzJbAssd both program-owned + spent |
| PASS | shield publicAmount encodes the deposit magnitude (public deposit) | publicAmount=0000000000000000000000000000000000000000000000000000000002faf080 |
| PASS | shield replay rejected (NullifierSpent) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x3; 7 log messages:   Program ComputeBudget111111111111111111111111111111 invoke [1]   Program Co |
| PASS | Alice scan recovered a SPENDABLE note from the enc blobs | recovered note .soak/notes-value/value-09a9aafa280190e439c0b221c5dc80aeb88e422ed99ee523f30900d443c4548d.json (spendable=true) |
| PASS | transfer carries NO cleartext amount (publicAmount == 0) | publicAmount=0000000000000000000000000000000000000000000000000000000000000000 |
| PASS | on-chain Transact bytes carry a zeroed publicAmount for the transfer | transact_data[1..33] (publicAmount) is 32 zero bytes |
| PASS | mutated public input rejected (ProofVerificationFailed) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0xc; 11 log messages:   Program ComputeBudget111111111111111111111111111111 invoke [1]   Program C |
| PASS | transfer advanced the value root (2 new output commitments) | commitment_count 2->4, root changed |
| PASS | transfer moved NO public lamports (vault unchanged) | vault 50890880 -> 50890880 |
| PASS | transfer created new nullifier PDAs (input note spent) | nf0=EsdZh4C3DeZjTmDuPKS6KAzP7tJWuSEfb3Z98HBPkWTR nf1=ZY2CPokAiKiaQssidL4wytT1Lm1PsGVWfhZqoyFHL9V both program-owned + spent |
| PASS | Bob scan auto-discovered his payment note (recipient-directed) | recovered note .soak/notes-value/value-1cd0563afb84d6c628f1a9f06a97a21f909b67677be5c1afc533887ec560eff7.json (spendable=true) |
| PASS | fresh recipient credited by the withdrawn amount | recipient GkdBCDGW5zpKo76eZr5z8zRAjZCjhbj94JBNRpdZtixv credited 20000000 lamports (= withdraw 20000000) |
| PASS | vault debited by exactly the withdrawn amount | vault debited 20000000 lamports |
| PASS | unshield advanced the value root | commitment_count 4->6, root changed |
| PASS | unshield created the input nullifier PDA (anti-replay) | nf0=8nJod3We2bRWvyUUDbBsm6S4j7jM1RkX5C1Bkqv89zoA program-owned + spent |
| PASS | fixed-denom shield of EXACTLY the denomination succeeds | vault2 credited 10000000 lamports (= denomination 10000000) |
| PASS | on-chain: wrong-denomination deposit rejected (DenominationMismatch) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x17; 7 log messages:   Program ComputeBudget111111111111111111111111111111 invoke [1]   Program C |
| PASS | CLI fail-fast: wrong-denomination shield refused client-side | Error: this value pool pins a fixed denomination of 10000000 lamports; a public deposit/withdraw must move exactly that amount (got 10000001)  |
| PASS | main vault balance == net public deposit - net public withdrawal | vault 30890880 == baseline 890880 + (shield 50000000 - withdraw 20000000) = 30890880 |

### Finalized transaction signatures + compute units

| flow | signature (Explorer) | commitment | CU consumed |
| --- | --- | --- | --- |
| init_value_pool_main | [`633jbqMtdEQhnAaDQw65x1FVDXM3uhfw3m51cjuSrNDjZxWRinmpTYsJo3MWRtxYV9Jh4UhxLRmhJxZtnL54SDss`](https://explorer.solana.com/tx/633jbqMtdEQhnAaDQw65x1FVDXM3uhfw3m51cjuSrNDjZxWRinmpTYsJo3MWRtxYV9Jh4UhxLRmhJxZtnL54SDss?cluster=devnet) | Finalized | 28964 |
| init_value_pool_denom | [`38MEi8RMsMyRTHpDbpZzfQdyfRBDJKCgS8D6M33qT9zYTccpK3NnpUqpJguVjWEuic9uhcht6kPgzq8HKC62nDQm`](https://explorer.solana.com/tx/38MEi8RMsMyRTHpDbpZzfQdyfRBDJKCgS8D6M33qT9zYTccpK3NnpUqpJguVjWEuic9uhcht6kPgzq8HKC62nDQm?cluster=devnet) | Finalized | 33503 |
| shield | [`5imt1JZEVZWrK7CtdsXBHJ4rdN5NxYEqGkXGwT47vddPeMcXzGFLSaxtW4qC7NMXd49nAjpr4GAZKXToTykMsUUf`](https://explorer.solana.com/tx/5imt1JZEVZWrK7CtdsXBHJ4rdN5NxYEqGkXGwT47vddPeMcXzGFLSaxtW4qC7NMXd49nAjpr4GAZKXToTykMsUUf?cluster=devnet) | Finalized | 196837 |
| transfer | [`2r6mo2YrDtjJP8bnVqRJXaVDgVLkxaAmtKAHvgkwYvWb8rchvd63QinFqbmuj5Gk2Se8M9g9ajcCkC5R6QNprtyv`](https://explorer.solana.com/tx/2r6mo2YrDtjJP8bnVqRJXaVDgVLkxaAmtKAHvgkwYvWb8rchvd63QinFqbmuj5Gk2Se8M9g9ajcCkC5R6QNprtyv?cluster=devnet) | Finalized | 197616 |
| unshield | [`54pTgcd2jdR2np3iWE3rHkihmdRhxEUKZbtCnoDLnaw9QC61WhqiySjfNnZohjNTwKhaABz7Bpo3gXuNxUKZFRzN`](https://explorer.solana.com/tx/54pTgcd2jdR2np3iWE3rHkihmdRhxEUKZbtCnoDLnaw9QC61WhqiySjfNnZohjNTwKhaABz7Bpo3gXuNxUKZFRzN?cluster=devnet) | Finalized | 202843 |
| denom_shield_exact | [`3KchDrW8rYNpQ6wzXBVGFPvv8aRc1YtdLxsPdiDrU99VbqPqYUadS3X7WKBpqkHDUDHZeTafWk9YXrqkeURasKVG`](https://explorer.solana.com/tx/3KchDrW8rYNpQ6wzXBVGFPvv8aRc1YtdLxsPdiDrU99VbqPqYUadS3X7WKBpqkHDUDHZeTafWk9YXrqkeURasKVG?cluster=devnet) | Finalized | 197077 |

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
#    from the one master payer (no per-key airdrops).
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

---

# Local Surfpool run (mainnet mirror)

The original run below is against a LOCAL Surfpool validator (a local mainnet
mirror), kept for completeness. Its signatures are local-validator signatures,
reproducible by re-running the soak against a fresh Surfpool, and are NOT
lookups on a public explorer (unlike the devnet section above).

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

> **Superseded for the membership circuit.** A separate, later ceremony - closed by a
> real public Solana mainnet-beta blockhash rather than a demo string - produced the
> membership key that is now committed and deployed. It is recorded in
> "Trusted-setup ceremony - the DEPLOYED membership key" further down, and in
> `docs/CEREMONY.md` section 10. Everything in *this* section is the earlier
> demonstration run, kept as captured. Where the text below says "the committed
> verifying key" it means the dev key that was committed at the time of capture;
> `circuits/artifacts/verification_key.json` today holds the ceremony key, so the
> `snarkjs groth16 verify` transcript below would no longer reproduce verbatim
> against that path. The transaction and association keys ARE still dev-setup keys.

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

# Trusted-setup ceremony - the DEPLOYED membership key

The run above is a demonstration. This one produced the membership verifying key
that is **actually committed and deployed**: `circuits/artifacts/vk.rs`,
`programs/mirror-pool/src/vk.rs`, the `MEMBERSHIP_VK_SHA256` pin in
`programs/mirror-pool/src/vk_digest.rs`, and the devnet program
`EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq`.

It is a **1-independent-contributor** ceremony. It is not a large ceremony and this
document does not present it as one; `docs/CEREMONY.md` section 10.3 states exactly
what it does and does not buy. The transaction (JoinSplit) and association keys are
**still dev-setup keys**.

## What it was

| item | value |
| --- | --- |
| circuit | `membership`, r1cs sha256 `8ed379951ad0b7371b4ac53fc373b64c36ac26552802ff165dad7af4977bd0a2` |
| phase 1 | public perpetual powers-of-tau, sha256 `1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922`, 55 contributions, `2^16` slice of a `2^28` ceremony |
| initial phase-2 key | sha256 `8c6b6c48195a4e116322cace04ec7619a9b158137bb98df37d9f78e651b15697` (deterministic from `snarkjs groth16 setup`) |
| steps | 2: one secret-entropy contribution (`marcelo@mirror-pool`, OS randomness + user entropy), then the closing beacon |
| independent contributors | **1** (the beacon is correctly not counted) |
| beacon | Solana mainnet-beta slot `435825712`, blockhash `9Gth2wVt86WhS1fh5FS7FihGvxyaesunW28M3zjD46Eu`, `2^20` SHA-256 iterations |
| beacon source string | `solana-mainnet-beta slot 435825712 blockhash 9Gth2wVt86WhS1fh5FS7FihGvxyaesunW28M3zjD46Eu` |
| final key digest | `f9d8f7f6423af7795efb379bd9686aaab2a7e5c7614e460247afb080e542c485` |
| final transcript hash | `884c88601173b1f08bd2e26626b0fe4c553dedffe707b2387db754417a9cdd05` |
| published transcript | `docs/ceremony-run/membership-deployed-transcript.json`, sha256 `7fcc51a3f2f846f080e134da127261a4215316d9336e5a1625c7ea9cebd381ab` |
| canonical vk | 769 bytes, sha256 `be5f776d2a4ba83655c50a9ecf47192cd3aa74075cd9e3d8a62bd99e043e4c76` |

`ceremony verify` reports `CEREMONY VERIFIED`, closed by beacon, and - when the
beacon value above is supplied - `beacon pre-commitment: checked against the value
you supplied`. Run WITHOUT that value it says `NOT supplied`, which is the honest
default, because the slot was chosen after the contribution rather than announced
in advance.

`ceremony prove-check` passes: it proves the membership circuit under the ceremony
proving key and the real `groth16-solana` verifier accepts the proof against the
ceremony-exported verifying key.

## Redeploy to devnet

The program was upgraded **in place**, so the program id and every explorer link in
this document survive:

```text
program id         EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq
upgrade signature  58gKGUdvKowyv4phxNUxKxiPbbnWNps9SKhxVkLWt7V8Q7DQLhrTuH2UWhUPtDzmeSPTEBExzXYeGVeYDuGFWHm
slot               479600717
upgrade authority  B2xLRxRKYTqusezsqhNZBPneJHsSCZn5L5ik8DqJQDGR
```

- Upgrade transaction: https://explorer.solana.com/tx/58gKGUdvKowyv4phxNUxKxiPbbnWNps9SKhxVkLWt7V8Q7DQLhrTuH2UWhUPtDzmeSPTEBExzXYeGVeYDuGFWHm?cluster=devnet
- Program: https://explorer.solana.com/address/EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq?cluster=devnet

The on-chain bytecode was dumped back and compared against the local build:

```text
on-chain dump      127680 bytes
local .so          127680 bytes
identical          yes (byte-for-byte, including the trailing zero padding)
sha256             6b026cf95e7f76d8a45c248004f98e2f647e7fc806203e1785bdeddcbea4f466
sha256 (padding stripped)  a5a19b4634e754a88d672604240ce87bc3a391abd07cace65d7c980ea0427566
```

```sh
solana program dump EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq /tmp/onchain.so --url devnet
cmp /tmp/onchain.so programs/mirror-pool/target/deploy/mirror_pool.so && echo IDENTICAL
```

## Verifying-key registry state on devnet

The registry is write-once per circuit. Had a membership registry account already
been initialized with the OLD dev key, no instruction could update it and the
upgraded program would reject it forever. It has not been:

```text
membership   6fkK14YXovKkJQ7z2Df7sBeCGPEnRK2XGBrRkMJJbRYg   AccountNotFound
transaction  BD1cm4jqbDHxgWX7ZfLmFaWWc1wSJFr5h68YesrkuCfW   AccountNotFound
association  3EyfUQZFSEz1VcTkCK3EsUV5uE8XqyCBmCQHETqjhWVn   AccountNotFound
```

checked both before and after the upgrade. So the FIRST `mirror-cli init-vk
--circuit membership` against this program installs the ceremony key, and the
pinned digest means that is the only key it can install.

## What a third party can check, and what they cannot

Reproducible from this repository and a devnet RPC:

```sh
# 1. the transcript, with no key files, beacon value supplied
make ceremony-verify-run

# 2. the committed key hashes to the constant the program pins
mirror-cli init-vk --circuit membership --dry-run \
  --program-id EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq \
  --payer <any keypair> --rpc-url https://api.devnet.solana.com
# -> sha256(vk): be5f776d2a4ba83655c50a9ecf47192cd3aa74075cd9e3d8a62bd99e043e4c76

# 3. the deployed bytecode is the bytecode in this tree
solana program dump EezWdFrmHtR2PCuucUruvkgyB9HW3w2KskZNeYmXszBq /tmp/onchain.so --url devnet
cmp /tmp/onchain.so programs/mirror-pool/target/deploy/mirror_pool.so

# 4. the vendored key equals the ceremony-exported artifact (header aside)
diff <(tail -n +9 programs/mirror-pool/src/vk.rs) circuits/artifacts/vk.rs
```

Not reproducible by a third party: the key-level ceremony checks (initial-key
binding, final-key binding, untouched-part equality, query scaling) and
`prove-check`, all of which need the 4.7 MB `.mpk` proving keys. Those are
gitignored build artifacts and are not published, exactly as for the demonstration
run. This document does not claim otherwise.

---

> **The funding-round evidence below is local-validator only.** The numbers were
> captured against a local Surfpool, which is where they were always claimed to
> come from. `mirror-soak-funding` publishes the JoinSplit verifying key through
> `init-vk` before it releases anything; the devnet program has since been
> upgraded to bytecode that has that instruction, but the funding soak has not
> been re-run against devnet, so nothing below is a public-cluster record.

<!-- funding-round-soak:begin -->
## Funding-round soak

This section documents an automated end-to-end run of `mirror-soak-funding` against a
LIVE local Surfpool validator (a local mainnet mirror at `http://127.0.0.1:8999`), treated as mainnet and
run honestly. It exercises the FUNDING-PROVENANCE path through the shipped components:
`mirror-cli shield | scan | fund-commit` on the participant side, and
`mirror_coordinator::FundingService` + `DirectoryIntake` on the coordinator side, which
polls the real chain slot, ingests the emitted requests, batches them into slot rounds,
and releases each round through the gasless relay. The signatures below are
local-validator signatures, reproducible by re-running the soak against a fresh Surfpool,
not lookups on a public explorer.

- generated: unix 1785196047
- program id (fresh deploy): `5uZEkrQv5EaEn4jsgnWvpW7pWcG7SLnU8HN7RGBLDBKU`
- funding ValuePool: `4KiYiBzpJ16W1nBcL5hWoFWdg1bQ7zEfsMwqwaUZGsU3` (authority / relay `7GAAPEMHQJb2xNgSEmoZHFdN3aMHBJ3JaYcUKWSjjRL8`), vault `FsSXtmoXAer8mux8UAhoxmqf29TvBeaagv6WKwHM6BS7`
- behavioral Pool: `JADctbdSkNk9ZoTuwuTH9vfpBu5FuCbLYWG53Zrwnk25`
- denomination: 100000000 lamports (every shield and every funding withdrawal moves exactly this)
- round: 12 slots, `min_round_size` 4, 4 participants; the released round was 408 at slot 4908

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

25/25 assertions passed.

| result | assertion | detail |
| --- | --- | --- |
| PASS | program deployed + executable | 5uZEkrQv5EaEn4jsgnWvpW7pWcG7SLnU8HN7RGBLDBKU |
| PASS | denominated funding ValuePool initialized (uniform amount enforced on-chain) | vpool=4KiYiBzpJ16W1nBcL5hWoFWdg1bQ7zEfsMwqwaUZGsU3 vault=FsSXtmoXAer8mux8UAhoxmqf29TvBeaagv6WKwHM6BS7 denomination=Some(100000000) |
| PASS | behavioral Pool initialized (the pool a funded commit wallet participates in) | pool=JADctbdSkNk9ZoTuwuTH9vfpBu5FuCbLYWG53Zrwnk25 epoch_slots=60 k_floor=2 |
| PASS | every participant shielded EXACTLY the denomination (uniform deposits) | vault credited 400000000 lamports = 4 x 100000000 |
| PASS | every participant recovered a SPENDABLE note by scanning | 4 notes recovered from the on-chain enc blobs |
| PASS | fund-commit minted a FRESH commit wallet per participant (all distinct, none a main wallet) | 4 distinct commit wallets |
| PASS | every fresh commit wallet is UNFUNDED before the round releases | no commit wallet had any lamports at request time |
| PASS | the coordinator INGESTED the fund-commit emits (the shipped intake path) | 3 request(s) batched into round 407 at slot 4887 |
| PASS | a round below min_round_size ROLLS FORWARD instead of releasing | round 407 held 3 < min_round_size 4 and moved to round 408 |
| PASS | a thin round reaches the chain NOT AT ALL (every commit wallet still unfunded) | all 4 commit wallets still at 0 lamports |
| PASS | the merged round RELEASED every batched withdrawal at its boundary | round 408 released 4 withdrawals at slot 4908 |
| PASS | every fresh commit wallet is credited EXACTLY the denomination | 4 wallets each credited 100000000 lamports |
| PASS | the pool vault was debited by exactly the sum released | vault debited 400000000 lamports (= 4 x 100000000) |
| PASS | every funding transaction carries EXACTLY ONE signature | signature counts: [1, 1, 1, 1] |
| PASS | that one signature is the RELAY's (fee payer at account key 0) | relay 7GAAPEMHQJb2xNgSEmoZHFdN3aMHBJ3JaYcUKWSjjRL8 |
| PASS | no funding transaction mentions ANY participant main wallet | 4 main wallets checked against 4 funding transactions |
| PASS | each fresh commit wallet's ONLY inbound transfer is from the pool vault | wallet F6QaK9m2B3K99eNAdkZDRRJjyFYBps4Nyv2uod6ToHhk: 1 transaction(s) in its entire history, 1 inbound, the only credit is 100000000 lamports debited from the vault FsSXtmoXAer8mux8UAhoxmqf29TvBeaagv6WKwHM6BS7 |
| PASS | the release order within a round is ARRIVAL-INDEPENDENT (same round, reversed arrival, identical release sequence) | arrival-order run ["F6QaK9", "2MXSpY", "HWB4KQ", "CVtJTA"] == reversed-arrival run ["F6QaK9", "2MXSpY", "HWB4KQ", "CVtJTA"] |
| PASS | the on-chain submission sequence IS the release order, not the arrival order | released ["F6QaK9", "2MXSpY", "HWB4KQ", "CVtJTA"] while participants arrived ["F6QaK9", "CVtJTA", "2MXSpY", "HWB4KQ"] |
| PASS | the funded commit wallet COMMITS to the behavioral pool, paying its own fee | epoch 81 commit_count=1 and the wallet paid 1118600 lamports out of its pool-funded balance |
| PASS | CLI fail-fast: a wrong-amount funding request is refused client-side | Error: this value pool is denominated at 100000000 lamports; --amount 100000001 would be rejected on-chain (DenominationMismatch) and a distinctive amount re-links the funder to the funded wallet anyway  |
| PASS | coordinator refuses an off-denomination request at the intake (no relay signature burned) | doctored-request.json: funding withdrawal of 100000001 does not match the pool denomination 100000000; a distinctive amount re-links the funder to the fundee |
| PASS | the refused request was quarantined, not batched | the doctored emit is in rejected/ and no round holds it |
| PASS | a mid-round submit failure RE-QUEUES the remainder instead of dropping it | the submit at release position 1 failed (submitting funding withdrawal in round 414 (index 3): send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0x3: 7 log messages: Program ComputeBudget11), and 3 of 4 withdrawals moved into round 415 |
| PASS | the withdrawal released BEFORE the failure still landed (partial release, honestly reported) | release position 0 (AjMP7JwzEgBzZ39CFEhYyVPnorXN22raVBNyoiY9CF1Y) is funded; the poisoned request at position 1 belonged to participant 3 (wallet 4nVyLCJAczDrwwoPH9nBqF1QD7wvyjY7wCtDRs3L8tq4) |

### Honest notes from this run

- the re-queued remainder keeps the FAILING request with it, so the same request fails again in the next round it lands in, releasing only the withdrawals ordered before it. The good requests still drain (the failing one drifts through the deterministic order), but a permanently-invalid request degrades round throughput until an operator removes it. FundingRounds has no quarantine policy for that today.

### Captured transaction signatures

| step | signature |
| --- | --- |
| init_value_pool_funding | `2ELXwLLYfuz7qT1C9Edy96fEtGUJdMPX12jvAmHmobgZhfSYLihpGjb66CQAbqzioppcSdpA2qEsvFm32sBEfHbD` |
| init_pool_behavioral | `5smnuF3DXc4FBQaYJzvxPpGyNLc8kLq4w47JgPMdT9t7YqHx6VH51dZVqVgNbEW9eKHxzo7PVXxfnHs21igdXedM` |
| shield_0 | `5FdQiBfwyetCFhWm8Svu7roCrSyQzLHTzdXjuKWYiQTMwr3JTaptT7Jn8WcnqDKjfagL8MyNKP8w4mkFHbeRRvMj` |
| shield_1 | `56T1cbVcfESxiCTuj3NUx3omP1tUmA6SSomjTmPcPCfvyxHzwPJWhxXHHzvK3XPRdTzeo6e1E2Ud4PEHAKwubHoG` |
| shield_2 | `2pk67NzadSPdxJSS8bJY1w4egwJiXWBj3ZCMkhZMXvMxoPxVqR82ch4vtAA3gMYsnNVr2cbxxxtcy17zMf7Vg8ui` |
| shield_3 | `4Ud3mFkqPAPEE1SYhYBBJpeZeZgQyQVxAt7tAcHPbASge4qDV6eKex6cuJRrDXkyYUGFHyq9sDB3uf4vrhaftzC8` |
| funding_release_0 | `2X6v3yZfHFE1eUayhUvChKie4rnJVu9zsb4joeGMAPRR4b2bKroj25m6WuXK1i36M2g4zDiK6s57Aj5w9er1Ayyx` |
| funding_release_1 | `2ZyxJvNYBrSVQHagKWXbujb6x1pA1kw9rXqUXxa2Kj3oUP7hqZKSjtf6C7h5eFE9H3yFct42ujzZ1GkMkZ4TnqQ6` |
| funding_release_2 | `5yLZo4exvQJYQKkJizgw4Ujj8u1vMkmEexqTyLLWYo6QsriENzLnXRGfq9NJVszfqkTaVfDs5o2kVcj8sxpTzyC3` |
| funding_release_3 | `57iVKcQwQikTZ5PB7p9zVQGvxhXmoqoaPD2xdWJ5JwoxB1ofyJU2aK5CU7UDMuvPqtGb3rPqhm4xJHjzyneHok2s` |
| commit_from_funded_wallet | `3YmiBaekvnLdCvRoqdMKfujdZFCfVAzGyUHVmddLDhKnJFAnjDkH5uPaWngam9wT1j6QRpJgMPNjgcPczrLQD5xD` |
| out_of_band_spend | `64gtFEgAMsg59WT5D3EZ7XjcSC6UFLzGern8B5csPGUWjdvJSbC3eFbjpixqBRcTBBJQ1VRw3LYGdBuxH6waCgbD` |

### Compute units (the released funding withdrawals)

| signature | compute units |
| --- | --- |
| `2X6v3yZfHFE1eUayhUvChKie4rnJVu9zsb4joeGMAPRR4b2bKroj25m6WuXK1i36M2g4zDiK6s57Aj5w9er1Ayyx` | 200588 |
| `2ZyxJvNYBrSVQHagKWXbujb6x1pA1kw9rXqUXxa2Kj3oUP7hqZKSjtf6C7h5eFE9H3yFct42ujzZ1GkMkZ4TnqQ6` | 193634 |
| `5yLZo4exvQJYQKkJizgw4Ujj8u1vMkmEexqTyLLWYo6QsriENzLnXRGfq9NJVszfqkTaVfDs5o2kVcj8sxpTzyC3` | 201994 |
| `57iVKcQwQikTZ5PB7p9zVQGvxhXmoqoaPD2xdWJ5JwoxB1ofyJU2aK5CU7UDMuvPqtGb3rPqhm4xJHjzyneHok2s` | 195070 |

### Reproduce

With a local Surfpool running at `http://127.0.0.1:8999` (treated as mainnet). That endpoint is whatever
`--rpc-url` was given for this run; `surfpool start --no-tui` listens on port 8899 by
default, and any other port here simply means the run was pointed at one.

```sh
# 1. build the on-chain program + host workspace
cargo build-sbf --manifest-path programs/mirror-pool/Cargo.toml
cargo build --workspace

# 2. deploy the program under a FRESH program id
solana-keygen new -o .soak/keys/funding-program.json
solana program deploy \
  --url http://127.0.0.1:8999 \
  --program-id .soak/keys/funding-program.json \
  programs/mirror-pool/target/deploy/mirror_pool.so

# 3. build the transaction-circuit artifacts (bash circuits/build_transaction.sh)

# 4. run the funding-round soak
cargo run -p mirror-soak --bin mirror-soak-funding -- \
  --rpc-url http://127.0.0.1:8999 \
  --program-id 5uZEkrQv5EaEn4jsgnWvpW7pWcG7SLnU8HN7RGBLDBKU
```

Every run creates a fresh pool, fresh main wallets, and fresh commit wallets, so the run
is self-contained and repeatable; the signatures above are from this run.
