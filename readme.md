# Nostr MMR implementation

Demo client using merkle mountain range (MMR) as an append only vector commitment for events (the same data structure used by opentimestamps in NIP-03) to enable fast verification (only a few events needed for proof of membership in the MMR).

This was briefly sketched [here](https://github.com/nostr-protocol/nips/issues/419)

In a Nostr event, we add tag MMR that includes the `prev_event_id` and the `prev_mmr_root` and the `prev_event_pos`.

``` rust
    Mmr {
        prev_event_id: Hash,
        prev_mmr_root: Hash,
        prev_event_pos: i64,
    }
```

The tag is defined [here](https://github.com/rust-nostr/nostr/compare/master...nostronaut:nostr:master#diff-f649b4ddb64afdb3f8ba22900c2ae1d2eef5ef4ef8c2f50757f40e169cf16e6cR378-R382)

We forked extracted code from [grin MMR](https://github.com/mimblewimble/grin/tree/master/core/src/core/pmmr) (which is monolithic): https://github.com/Pencil-Yao/cloud-mmr/compare/master...nostronaut:cloud-mmr:master and replaced the crypto to `bitcoin_hashes`

Example of 8 chained events using this demo code:

<-[event 0](https://www.nostr.guru/e/a8940e20263aea085b8f694b2bdd376a52cdff571715536909a060b47f72e05f)
<-[event 1](https://www.nostr.guru/e/f1e1b30af9bdefa7e29d32a9f4145c26a9aa6feada4aea07832a2cf14a781bc2)
<-[event 2](https://www.nostr.guru/e/ae505067e4dccb1cc9ddc44dd08a542b85d6db1e3d853e3d37fdc717ee0433a8)
<-[event 3](https://www.nostr.guru/e/8698f3735890708569c5e0b5a5e2934b562d7f13076b5ea5fdbf7582583f023f)
<-[event 4](https://www.nostr.guru/e/e6f53802752de6c55a24ee727ed5ce8e4a5fe47d5aab376cf9c8e6845629abb9)
<-[event 5](https://www.nostr.guru/e/dae39999037b1240bea8a0ad6d417ae1148e0d95fcd6cea101dce894efadc78c)
<-[event 6](https://www.nostr.guru/e/84584faf43127be13521e6ed5ef733d0a7007847214afedec7019874951cc34c)
<-[event 7](https://www.nostr.guru/e/fe27dfe68c887f3a3553ad72973f3d4ff7350e716d59a441880e2c221f15a99f)

The encoded MMR encoded in the MMR tag looks like this:

```
2            111
           /     \
1         11     110       1010
         /  \    / \      /    \
0       1   10 100 101  1000  1001  1011
event   e0  e1  e2  e3   e4    e5    e6    e7
```
