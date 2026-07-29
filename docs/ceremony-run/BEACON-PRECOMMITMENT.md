# Beacon pre-commitment

This file is committed BEFORE the beacon value exists. That is the whole point: a
beacon only removes the last contributor's ability to grind the final key if the
source was fixed in advance, where "in advance" means published before the value
could be known.

The membership ceremony already deployed did NOT have this. Its beacon was a real
public Solana blockhash, but the slot was chosen after the fact, so a verifier
cannot rule out that the operator shopped for a favourable one. That limitation is
stated wherever that ceremony is described, and it is the gap this file closes for
the ceremonies that follow.

## The commitment

- Chain: Solana mainnet-beta
- Slot: **435846661**
- Announced at slot: 435842661 (i.e. this file names a slot roughly 25 minutes in the future)
- Rule: the beacon source string is
  `solana-mainnet-beta slot 435846661 blockhash <the blockhash of that slot>`

Nobody, including the operator, can predict the blockhash of slot 435846661 at the
time this file is written. Anyone can fetch it afterwards and recompute the beacon
scalar to check that the ceremonies below closed on exactly this value.

## Ceremonies closed with it

- `transaction` (the confidential-value JoinSplit circuit)
- `association` (the opt-in compliance circuit)

Verify with:

```sh
mirror-cli ceremony verify --dir <dir> \
  --beacon-source-text "solana-mainnet-beta slot 435846661 blockhash <blockhash>"
```
