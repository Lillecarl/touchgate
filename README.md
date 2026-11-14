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

- **SSH security key:** an `ed25519-sk` key on the YubiKey signs the
  challenge; the broker checks it with `ssh-keygen -Y verify`. From a
  pymux pane on another machine, this needs agent forwarding over the
  pymux link (Lillecarl/pyterm#986).
- **WebAuthn:** the broker serves an approval page; the person opens it
  and touches the key in the browser. Works without pymux.

## Configuration

`~/.config/touchgate/config.toml`:

    email = "you@example.com"
    server = "eu"                          # us, eu, or a self-hosted URL
    signing_key = "~/.ssh/id_ed25519_sk"   # or a .pub whose key is in the agent

## What this does not stop

- A process that receives a secret can print it. An approved
  `touchgate run db -- env` gives the value away.
- The requesting process prints the prompt, so a changed client can
  print one thing and ask for a signature over another. The touch binds
  the challenge bytes, not what the person read. A display that the
  requester does not control (the pymux plugin, a WebAuthn page) closes
  this.
- While an approved command runs, every process of the same user can
  read its environment from `/proc/<pid>/environ`. That is true in both
  modes.
- With `--client-exec`, the command line is the client's claim. A
  changed client can use the values for another command.
- The environment and working directory of a broker run are the
  client's. The broker drops `LD_*` and `DYLD_*`, but a variable or a
  file in the directory can still steer the command.
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
