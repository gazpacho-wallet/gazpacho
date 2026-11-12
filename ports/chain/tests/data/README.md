# Recorded chain server answers

Response bodies saved byte for byte from public chain servers on 2026-11-11, from the project's build server, with `curl`. The unit tests feed them to the Esplora backend through a fake transport, so no test in the default run touches the network. They are also the starting corpus for the mutation tests and for a real fuzzer later.

Unless a file name says otherwise, mempool.space and blockstream.info returned exactly the same bytes for the request (compared with `cmp` when recorded), so one copy is kept.

## Signet

Base addresses: `https://mempool.space/signet/api` and `https://blockstream.info/signet/api`.

The subject is transaction A, `8690387a65262437580d45b77f1cb0792faff46cecb72c5ee22390e5193a6c9a`, at position 1 of block 329438. Its output 0 is spent by input 0 of the "spender", `ee18add119d09dc5b01cde93367391947495b656c30c5935cbde8374aa9d944b`, in block 329439. Its output 2 pays 43000 sat to the script `0014ea6f435d306838385ae16fa43b0cebb6c2f0cdb9` and was unspent when recorded. Transaction B, `a8f29683fcf6687b0944580cca8ee91b44c7ce3fa79fddcafc3c33334e5f411f`, is at position 2 of the same block.

| File | Request |
|---|---|
| `block_hash_329437.txt`, `..38`, `..39` | `GET /block-height/{height}` |
| `header_329437.txt`, `..38`, `..39` | `GET /block/{hash}/header` |
| `tx_a_status.json`, `tx_b_status.json`, `tx_spender_status.json` | `GET /tx/{txid}/status` |
| `tx_a_hex.txt`, `tx_spender_hex.txt` | `GET /tx/{txid}/hex` |
| `tx_a_merkle_proof.json`, `tx_b_merkle_proof.json`, `tx_spender_merkle_proof.json` | `GET /tx/{txid}/merkle-proof` |
| `tx_a_outspend_0.json` (spent), `tx_a_outspend_2.json` (unspent) | `GET /tx/{txid}/outspend/{vout}` |
| `utxo_script_a2.json` | `GET /scripthash/c7ecf6689f2f6ac8edddcd98b48ab7ab6283d59ccf1c692124f86ba503387cd0/utxo`. The key is SHA-256 of the script, not reversed. The reversed key returned `[]` on both servers |
| `fee_estimates_mempool.json` | `GET /fee-estimates` on mempool.space (HTTP status 203) |
| `fee_estimates_blockstream.json` | `GET /fee-estimates` on blockstream.info (HTTP status 200) |
| `post_known_mempool.txt`, `post_known_blockstream.txt` | Body of the HTTP 400 answer to `POST /tx` with transaction A, which was already confirmed. The two operators word the refusal differently |

## Other networks (header and transaction checks only)

| File | Request |
|---|---|
| `mainnet_header_0.txt`, `mainnet_header_1.txt` | `GET https://blockstream.info/api/block/{hash}/header` for mainnet blocks 0 and 1 |
| `mainnet_legacy_tx_hex.txt` | `GET https://blockstream.info/api/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16/hex`, a transaction with no witness data |
| `testnet4_header_a.txt`, `testnet4_header_b.txt` | `GET https://mempool.space/testnet4/api/block/{hash}/header` for testnet4 blocks 160697 and 160698 |

Answers that are short fixed strings (`{"confirmed":false}`, `{"spent":false}`, `Block not found`, `Transaction not found`) are written in the tests directly; they were observed on both servers the same day.
