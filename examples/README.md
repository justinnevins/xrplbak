# Examples

- `xrpld.cfg.example`, `validators.txt.example`: obviously fake configs to try `xrplbak redact` and `xrplbak backup` (dry run) against.
- `verify-bundle.sh`: a reference shell snippet that checks a bundle file's hash against a manifest printed by `xrplbak verify --json`. It is an illustration, not the tool.

```
cp examples/xrpld.cfg.example ./xrpld.cfg
cp examples/validators.txt.example ./validators.txt
xrplbak init --yes
xrplbak backup
```
