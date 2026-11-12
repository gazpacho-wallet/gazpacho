# Gazpacho

A self-contained Bitcoin Lightning wallet for [SuperScalar](https://github.com/8144225309/SuperScalar) channel factories.

One program lets you **join** a factory, where many people share a single on-chain output and each gets a Lightning channel, or **host** one. It needs no Bitcoin node, no separate Lightning node and no modified node software: Gazpacho carries its own small Lightning node and reads the chain from Electrum-style servers, or from your own node if you have one.

**Status: planning. Nothing here is usable yet. The first release will be signet-only.**

- [Knowledge base: start here](docs/KNOWLEDGE-BASE.md)
- Everything in one page: `docs/handbook.html` (open it from disk)
- [Plan](docs/PLAN.md)
- [Design](docs/DESIGN.md), with the [dated record](docs/RECORD.md) of how it got there
- [Testing plan](docs/TESTING.md) and [specifications](spec/)
- [The lobby](docs/LOBBY.md)
- [Lightning nodes a host can link to](docs/HOST-NODES.md)
- [Open questions](docs/OPEN-QUESTIONS.md)
- [Proposing a rule or feature](docs/sips/README.md)
- [Contributing](CONTRIBUTING.md) and [security](SECURITY.md)
- [What existed at the start and what has to be built](docs/ASSESSMENT.md)

## Dedication

To Keonne Rodriguez, William Lonergan Hill, Roman Storm, Alexey Pertsev, and everyone who paid for our freedom to hold our own keys. [Read the dedication](DEDICATION.md).

## Licence

MIT
