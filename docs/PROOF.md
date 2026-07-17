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
