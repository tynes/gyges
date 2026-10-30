# Gyges Documents

Where to look, by question:

| Question | Read |
|---|---|
| How is the daemon put together? What does each component do? | [`architecture.md`](architecture.md) Components |
| How does a key sync, backfill below the node's window, or survive a reorg? | [`architecture.md`](architecture.md) Sync |
| What files does the daemon write, and what is in them? | [`architecture.md`](architecture.md) Data model |
| What does a `gyges` command do, and what does it exit with? | [`interface.md`](interface.md) CLI |
| What does an RPC do, and how do errors, streams and signing sessions work? | [`interface.md`](interface.md) API, and [`proto/gyges.proto`](../proto/gyges.proto) |
| Who is the adversary, and which test proves each control? | [`security.md`](security.md) |
| How is it tested, and how do I run the regtest scenarios or benchmarks? | [`testing.md`](testing.md) |
| Why was it built this way? What does the Zakura node actually do? | [`decisions.md`](decisions.md) §1–2 |
| What is not done yet? | [`decisions.md`](decisions.md) §3 |
| What does a term mean? | [`glossary.md`](glossary.md) |

## Conventions

- **Section references** take the form `architecture.md Sync §4.2`. `architecture.md` and `interface.md` are split into parts, and section numbers restart in each part. Within a part, a bare `§` means that part.
- **Decision IDs** (`Q-D3`, `Q-S4`, …) are stable. They are defined in `decisions.md` §1, and code comments cite them directly.
- **The documents describe what was built.** When a change alters a design, update the section it cites in the same change, and record any deviation from a decision under that decision. When a change leaves something out, add it to `decisions.md` §3.
- **Some examples are tested.** The `config.toml` examples in `architecture.md` Components §4 and Data model §2, and the `profile.json` example in Data model §3, are parsed by the `gyges-core` tests. The CI job also parses every TOML block in `architecture.md`. Keep them valid.
