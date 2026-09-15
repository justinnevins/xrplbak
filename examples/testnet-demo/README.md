# Testnet demo (offline)

A real backup of the fake example config, made on the XRPL Testnet on 2026-09-15 from account `rDCbTpTs2BLD8AH4AuhtqtnkqGMnDZ3xTR`. The recovery words in `words.txt` are published on purpose: the config is fake and the account holds test XRP only. Never publish the words of a real backup.

The demo is offline. It reads the dump file, so it keeps working after a Testnet reset.

```
xrplbak verify  --dump examples/testnet-demo/demo.dump.json --account rDCbTpTs2BLD8AH4AuhtqtnkqGMnDZ3xTR --words-file examples/testnet-demo/words.txt --bundle examples/testnet-demo/demo.bundle
xrplbak restore --dump examples/testnet-demo/demo.dump.json --account rDCbTpTs2BLD8AH4AuhtqtnkqGMnDZ3xTR --words-file examples/testnet-demo/words.txt --bundle examples/testnet-demo/demo.bundle
```

Files:
- `demo.dump.json`: the four validated transactions (one chunk, two manifest parts, the DID anchor). Ciphertext and public data only.
- `demo.bundle`: the encrypted off-chain bundle (validator token and topology of the fake config).
- `words.txt`: the 24 recovery words for this demo only.
