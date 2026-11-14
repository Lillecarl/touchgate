# touchgate

Run a command with secrets from a Bitwarden vault, once a person
approves the run with a hardware key touch.

    touchgate run [--env NAME=SOURCE]... <secret> -- <command> [args...]

The command gets the secret as environment variables. No secret lives
in a file. Each custom field whose name is a variable name becomes that
variable; `--env PGPASSWORD=password` adds the username, password,
notes or another field under a name of your choice.

## Why

An agent needs credentials to do real work. A credential in a file is
readable by every process of the user, and every agent. touchgate
keeps them in the vault and hands one out per run, after the person
has seen what asks for it.

## Parts

- **Broker:** a user service. It holds the unlocked vault in memory and
  listens on a unix socket. It is its own Bitwarden client: it speaks
  the Bitwarden API and does the vault cryptography itself, with no
  `bw` process beside it. Its tests run against Vaultwarden.
- **`touchgate run`:** sends a request to the broker, gets the
  challenge signed with `ssh-keygen -Y sign`, and sends the signature
  back. By default the broker then starts the command itself, on the
  client's stdin, stdout and stderr, and the values never reach the
  client. With `--client-exec` the client receives the values and
  execs the command.
- **Approval:** the broker builds a challenge from the secret name, the
  exact command line, the working directory, the requester (the pymux
  pane, from `$PYMUX`), who starts the command, and the variable names.
  The person signs it with a hardware key, and the broker verifies the
  signature itself. The challenge carries a nonce and an expiry, and a
  request is used by its first approve attempt, so a captured signature
  does not approve a second run. An `sk` signature made without user
  presence (no touch) is refused: `ssh-keygen -Y verify` does not check
  that, so the broker reads the signature itself.
- **Approvers:** the notes of the vault item `touchgate-approvers` list
  the public keys that may approve, one per line, as OpenSSH writes
  them. Only `sk-ssh-ed25519` and `sk-ecdsa-sha2-nistp256` keys count.
  The list lives in the vault because a local process cannot write
  there. A software key can make a signature that looks like a hardware
  one, so whoever can edit the list can approve.

## The rule

**The broker trusts a signature, never a user interface.** Agents
drive terminals: an agent can press "approve" in any prompt it can
reach, pymux's included. A UI may show a request and carry its
challenge. Only a hardware key signature that the broker verifies
grants a secret.

## Approval routes

- **SSH security key here:** with `signing_key` set, `touchgate run`
  signs the challenge with `ssh-keygen` and an `ed25519-sk` key on the
  YubiKey. The broker verifies the signature itself.
- **SSH security key on a linked pymux:** with no `signing_key`, the
  request waits for a signature from elsewhere. The pymux plugin where
  the broker runs asks the touchgate plugin on each linked pymux server
  in turn. On the machine with the key, a popup shows the request, and
  `ssh-keygen` there signs it with a touch. The signature crosses the
  pymux link, and the broker verifies it on arrival. A machine with the
  key answers only a server its own pymux dialled.

## Grants

One touch can approve later runs too. An agent such as Claude Code
then runs a deploy command again and again, with no touch each time:

    touchgate run --grant 8h deploy -- ./deploy.sh prod

The grant holds for one process and every process under it: the
anchor. By default the anchor is the nearest Claude Code process above
`touchgate`; `--grant-to PID` names another. The broker reads the
anchor's name, directory and start time from `/proc` itself, and
refuses an anchor that is not a parent of the process that asks, or
that is a parent of the broker too. The challenge holds the grant
terms, so the popup shows them before the touch.

A later request runs under the grant with no touch when the anchor is
one of its parents and the request names the same item, the same
variables and the same command. `--grant-prefix N` matches only the
first N words of the command. Only the broker starts a granted
command; a grant takes no `--client-exec`.

A grant ends at its time limit (at most 24 hours), after
`--grant-uses N` runs, when the anchor exits, when the broker locks,
or on `touchgate revoke ID` (`--all` ends every grant).
`touchgate grants` lists them as JSON. The watch reports each run
under a grant as a `run` event.

A grant challenge is signed under its own SSHSIG namespace,
`touchgate-grant`. A touchgate without grants shows such a challenge as
one plain run and signs it under `touchgate`, and the broker refuses
that signature. A touchgate refuses to sign a challenge with fields it
cannot show.

## Unlocking

The broker starts locked. Three ways open it:

- `touchgate unlock` asks for the master password.
- A systemd credential `touchgate-password` unlocks it at start. Read
  the limits below first.
- A security key with the FIDO2 PRF (hmac-secret), such as a YubiKey.
  The key's PRF gives the same 32 bytes on every touch, and those seal
  the master password. This runs where the key is plugged in:

      touchgate enroll    # two touches; writes ~/.config/touchgate/sealed-password.json

  The sealed file opens only with that key, touched. A request that
  waits for a signature from elsewhere also waits for a locked broker to
  unlock. The pymux plugin then asks the linked machine with the key: a
  popup there says which server asks, and a touch opens the sealed
  password. The password crosses the pymux link to the broker. Without
  pymux, `touchgate unlock --yubikey` does the same over a socket that
  `TOUCHGATE_SOCKET` names, such as one forwarded by `ssh -L`.

## The pymux popup

`touchgate show <id>` prints a request as the broker holds it, and
waits until it ends. The pymux plugin runs it in a popup in the session
of the pane that asked, for every request whose `$PYMUX` names that
server. The plugin is one file with no dependencies beyond pymux's own:

    ln -s $(python -c 'import touchgate.pymux_plugin as p; print(p.__file__)') \
      ~/.config/pymux/plugins/touchgate.py

From Nix, the package names the file as `touchgate.pymuxPlugin`:

    xdg.configFile."pymux/plugins/touchgate.py".source = touchgate.pymuxPlugin;

`touchgate` must be on the PATH of the pymux server. Install the plugin
on both machines: where the broker runs, and where the key is plugged
in. The pymux link between them needs pymux with plugin messages
(Lillecarl/pyterm#988) on both ends.

## Configuration

`~/.config/touchgate/config.toml`:

    email = "you@example.com"
    server = "eu"                          # us, eu, or a self-hosted URL
    signing_key = "~/.ssh/id_ed25519_sk"   # or a .pub whose key is in the agent;
                                           # leave it out to sign on a linked pymux

## What this does not stop

- A process that receives a secret can print it. An approved
  `touchgate run db -- env` gives the value away.
- The requesting process prints its own prompt, so a changed client
  can print one thing and ask for a signature over another. The touch
  binds the challenge bytes, not what the person read. Read the request
  in the pymux popup, which shows what the broker holds. A process that
  drives pymux can still open a popup of its own that looks the same.
- While an approved command runs, every process of the same user can
  read its environment from `/proc/<pid>/environ`. That is true in both
  modes.
- With `--client-exec`, the command line is the client's claim. A
  changed client can use the values for another command.
- The environment and working directory of a broker run are the
  client's. The broker drops `LD_*` and `DYLD_*`, but a variable or a
  file in the directory can still steer the command.
- A grant narrows; it is no sandbox. Every process of the user that
  can ptrace the anchor can start a child under it, and that child
  runs under the grant. A grant also trusts the pid that `SO_PEERCRED`
  records at connect: a process that exits, and gives its pid to a new
  process before the broker reads `/proc`, is mistaken for the new one.
  Grants need `/proc`, so they work only on Linux.
- A security key has no display. A touch approves whichever signature
  request reaches the key first.
- Everything here runs as one user. A process that can replace the
  broker's unit or binary can wait for the next unlock and read the
  master password.
- In a user unit, systemd puts a credential in
  `$XDG_RUNTIME_DIR/credentials/<unit>/`, and every process of the user
  can read it while the unit runs (measured on systemd 261). The
  credential unlock route therefore gives the master password to every
  local process.

A broker run has no controlling terminal. It reads and writes the
client's terminal, but a program that opens `/dev/tty` fails. Ctrl-C
and other signals reach it through the client, and Ctrl-Z stops only
the client. The run lives in the broker's unit, under its cgroup and
sandbox settings, and a broker restart ends it.
