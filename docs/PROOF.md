# mirror-pool - live Surfpool soak proof

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

# 3. (ZK path) ensure snarkjs + the circuit artifacts are present
#    circuits/membership_final.zkey, circuits/membership_js/membership.wasm,
#    circuits/artifacts/verification_key.json  (build with `bash circuits/build.sh`)

# 4. run the soak (defaults target the running Surfpool + the built program id)
cargo run -p mirror-soak -- \
  --rpc-url http://127.0.0.1:8899 \
  --program-id 7vUgz7eMA2HD1DrTrKp3YWvUgpmyyrab8ogmnfdHhuve \
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
participant CLI (`mirror-cli`, which proves with snarkjs and emits each Transact) and
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
| PASS | Alice scan recovered a SPENDABLE note from the enc blobs | recovered note /Users/marcelofeitoza/Development/solana/cloak/extra/noise-bounty-claude/mirror-pool/.soak/notes-value/value-28c794b627ef7973b8737cd27f2564d0f1fceca3b1f9fb11dcc6155a125604ff.json (spendable=true) |
| PASS | transfer carries NO cleartext amount (publicAmount == 0) | publicAmount=0000000000000000000000000000000000000000000000000000000000000000 |
| PASS | on-chain Transact bytes carry a zeroed publicAmount for the transfer | transact_data[1..33] (publicAmount) is 32 zero bytes |
| PASS | mutated public input rejected (ProofVerificationFailed) | send_and_confirm_transaction: RPC response error -32002: Transaction simulation failed: Error processing Instruction 2: custom program error: 0xc: 11 log messages: Program ComputeBudget111111111111111111111111111111 invoke [1] Program Compu |
| PASS | transfer advanced the value root (2 new output commitments) | commitment_count 2->4, root changed |
| PASS | transfer moved NO public lamports (vault unchanged) | vault 500890880 -> 500890880 |
| PASS | transfer created new nullifier PDAs (input note spent) | nf0=3XXRMvuUGdZNHHPeBw5Ky798LjzHdCnN3f5QhVZXDkbx nf1=GF4sZMEoDirKpaBhdooevKP2GctGVv5AyWm4rUChYBfq both program-owned + spent |
| PASS | Bob scan auto-discovered his payment note (recipient-directed) | recovered note /Users/marcelofeitoza/Development/solana/cloak/extra/noise-bounty-claude/mirror-pool/.soak/notes-value/value-28eeb3512c04468d96ee2fe83b0f4ec66b6b5182d3023dddc27f2e3bc37971f7.json (spendable=true) |
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

# 3. ensure snarkjs + the transaction-circuit artifacts are present
#    circuits/transaction_final.zkey, circuits/transaction_js/transaction.wasm,
#    circuits/artifacts/transaction_verification_key.json

# 4. run the confidential-value soak against the fresh program id
cargo run -p mirror-soak --bin mirror-soak-value -- \
  --rpc-url http://127.0.0.1:8899 \
  --program-id BDhUdkZeHrk1cNG2Yss6Z5jTMHEkqqvPiJJTAZSSmFti
```

Every run creates fresh pools (fresh relay authorities) and fresh wallets, so the run
is self-contained and repeatable; the signatures above are from this run.
