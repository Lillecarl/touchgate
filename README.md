# touchgate

Run a command with secrets from a Bitwarden vault, once a person
approves the run with a hardware key touch.

    touchgate run <secret> -- <command> [args...]

The command gets the secret as environment variables. No secret lives
in a file.

## Why

An agent needs credentials to do real work. A credential in a file is
readable by every process of the user, and every agent. touchgate
keeps them in the vault and hands one out per run, after the person
has seen what asks for it.

## Parts

- **Broker:** a user service. It holds the unlocked vault in memory and
  listens on a unix socket.
- **`touchgate run`:** sends a request to the broker and waits. On
  approval it receives the values, sets them in the environment, and
  execs the command.
- **Approval:** the broker builds a challenge from the secret name, the
  exact command line and the requester (the pymux pane, from `$PYMUX`).
  The person signs it with a hardware key, and the broker verifies the
  signature itself.

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

## What this does not stop

A process that receives a secret can print it. An approved
`touchgate run db -- env` gives the value away. So the prompt shows
the exact command, and the broker may bind a secret to the commands
allowed to receive it.
