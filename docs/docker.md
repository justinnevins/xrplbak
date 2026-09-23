# Running xrplbak with a validator in Docker

Run xrplbak on the host, not inside the container. A container image of
xrpld keeps its config in a folder on the host that is mounted into the
container. xrplbak reads and restores that host folder. It never talks to
the container: backup and restore reach the ledger through whichever XRPL
server you name with `--rpc`.

## Find the host folder

    docker inspect xrpld --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}'

With the XRPL Labs image (`xrpllabsofficial/xrpld`) the config folder is
mounted at `/config/` in the container, for example
`-v /srv/xrpld-config/:/config/`. The image copies `xrpld.cfg` and
`validators.txt` from there when the container starts. The examples below
use `/srv/xrpld-config` as the host folder.

## Keep the key file out of the mounted folder

xrplbak looks for `xrplbak.key` next to the config by default. In Docker
that folder is visible inside the container. Keep the key file somewhere
else on the host and pass `--key`:

    xrplbak init --out /root/xrplbak

## Back up

    xrplbak backup --config /srv/xrpld-config/xrpld.cfg --key /root/xrplbak/xrplbak.key
    xrplbak backup --config /srv/xrpld-config/xrpld.cfg --key /root/xrplbak/xrplbak.key --submit --rpc mainnet

If `[validators_file]` names `validators.txt` (a relative path), it resolves
beside the config on the host and needs nothing more.

If it names an absolute path that exists only inside the container, such as
`/etc/xrpld/validators.txt`, the host cannot see it and backup stops:

    config names [validators_file] /etc/xrpld/validators.txt but it does not exist; fix the config or pass --validators PATH

Point it at the host copy. The line in your config stays as it is, so the
container keeps working:

    xrplbak backup --config /srv/xrpld-config/xrpld.cfg --validators /srv/xrpld-config/validators.txt --key /root/xrplbak/xrplbak.key

## Restore

1. Restore to a temporary folder first and read the report:

       xrplbak restore --rpc mainnet --account <address> --bundle <file>

2. Stop the old container if it still runs anywhere. One validator token
   must run in one place.
3. Write the files into the host folder that the new container mounts:

       xrplbak restore --rpc mainnet --account <address> --bundle <file> --write --target /srv/xrpld-config

   `--write` refuses to replace files that already exist. Add `--force`
   only when you mean to overwrite them.
4. Start or restart the container so it picks up the files:

       docker restart xrpld

5. Confirm `server_info` shows the expected `pubkey_validator`.

## Tested

`cmd/xrplbak/docker_layout_test.go` covers the three layouts: a relative
`[validators_file]` beside the host config, an absolute path that exists
only in the container (refused, then backed up with `--validators` and
restored byte for byte into a fresh host folder), and an absolute path that
exists on the host. No container runtime was used in the test. The
behavior is the same because xrplbak only ever touches host files.
