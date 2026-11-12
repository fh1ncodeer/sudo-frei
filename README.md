# sudo-frei

*frei* is German for "free": passwordless sudo, for a while.

Time-limited passwordless `sudo` on your own Linux machines, controlled over SSH from one machine. `sudo-frei` is a small TUI that shows every grant with a countdown, plus the state of your SSH agent; `sudo-frei-cli` does the actual work and can be used on its own.

Meant for stretches of admin work (yours, or an agent's) where typing the password for every command gets in the way, and where everything must be back to normal afterwards.

```
sudo-frei                         # the TUI
sudo-frei-cli grant server 30     # 30 minutes of passwordless sudo on "server"
sudo-frei-cli status              # all hosts from the config
sudo-frei-cli revoke server       # end it early
```

## How it works

Nothing is installed on the target. `sudo-frei-cli` sends its code over SSH with every call. A grant creates three things in **one** sudo call:

1. **Rule:** `/etc/sudoers.d/zz-sudo-frei` with `USER ALL=(ALL:ALL) NOTAFTER=<deadline> NOPASSWD: ALL`. Classic sudo ignores the rule after the deadline on its own, even if everything else fails; sudo-rs does not know `NOTAFTER`, so there the rule goes without it. The rule is written by root under a name sudo skips, checked with `visudo -c`, and renamed into place atomically.
2. **Timer:** a one-shot systemd timer with a fixed expiry time in UTC. It deletes the rule, the marker and the user's sudo timestamps.
3. **Reboot cleanup:** `/etc/tmpfiles.d/sudo-frei.conf` deletes rule and marker at boot, in case the timer is lost.

Plus `/run/sudo-frei-until`, holding the expiry time and readable without privileges. `status` reads the state from it.

The deadline is computed after sudo has accepted the password, so slow typing does not eat into the window. Grant and revoke take a lock in a root-only directory (`/run/sudo-frei/lock`), so they never interleave. The timer does not wait for it: firing during a grant can only remove a rule early. After a grant, `sudo -n -k true` checks that the rule really works without a password; if not, it is removed again.

| Case | Behaviour |
|---|---|
| Time runs out | the timer deletes the rule, to about 1 s |
| Suspended past the expiry time | deleted on wake-up |
| Reboot | deleted at boot |
| Connection drops, Ctrl-C | the root part ignores HUP/INT/TERM and runs to the end |
| A re-grant fails before the switch | the previous grant stays, timer included; the new timer is cancelled |
| The switch itself fails halfway | everything is removed (fail-safe: off) |
| The final `visudo -c` fails | everything is removed (fail-safe: off) |
| `revoke` | deletes the rule first, then the timers |
| Rule without a timer, or past its deadline | `status` reports **orphan** instead of "off" |
| Clock set back by root or NTP | the timer fires later by that much; with classic sudo `NOTAFTER` follows the same clock |

## The trade-off

During a grant the user is effectively root, without being asked. That applies to every process running as that user, and to anyone who can use the SSH key. Keep windows short, especially on publicly reachable servers.

## Requirements

- **Controlling machine:** bash, ssh, python3 ≥ 3.11 (for `tomllib`); Rust ≥ 1.88 for the TUI.
- **Targets:** Linux with systemd, sudo and `flock` (util-linux), SSH login as a regular user with sudo rights and a plain lowercase user name.
- **Tested on real hosts:** grant, timed expiry, early revoke and the NOTAFTER rule on Arch (systemd 262, sudo 1.9.17p2); grant and timed expiry on Debian 13 (systemd 257, sudo 1.9.16p2).
- **Ubuntu 25.10+ with `sudo-rs`:** intended, but untested.
- **Raspberry Pi OS:** ships `/etc/sudoers.d/010_pi-nopasswd`, so sudo is already passwordless for good there. sudo-frei only makes sense once that file is removed.

## Install

```
ln -s "$PWD/scripts/sudo-frei-cli" ~/.local/bin/sudo-frei-cli
cargo install --path .            # installs the TUI as sudo-frei
mkdir -p ~/.config/sudo-frei
cp config.example.toml ~/.config/sudo-frei/config.toml   # add your hosts
```

## Configuration

`~/.config/sudo-frei/config.toml`, see `config.example.toml`. `sudo-frei-cli` reads `hosts`, `status_timeout` and `status_timeout_proxy`; the TUI also reads `presets`, `default_minutes`, `refresh_seconds` and `script`.

`status` asks all hosts at once and reports a host as unreachable after `status_timeout` seconds (default 2.3). Hosts that ssh reaches through a `ProxyJump` or `ProxyCommand` get `status_timeout_proxy` (default 8), because two handshakes rarely fit into the short one.

## TUI

| Key | |
|---|---|
| ↑↓ | select host |
| g | grant (type minutes or ←→ for presets) |
| r | revoke |
| a | add an SSH key (`ssh-add`) |
| x | clear the agent |
| u | refresh |
| q | quit |

The **SSH key** column shows per host whether the key from `ssh -G HOST` is loaded in the agent. For password and passphrase prompts the TUI hands the terminal to `sudo-frei-cli` or `ssh-add`. All sudo logic lives in `sudo-frei-cli`; the TUI only calls it.

## Tests

```
scripts/sudo-frei-test    # the root flow in a scratch directory, no sudo/ssh
cargo test
```

## License

MIT, see [LICENSE](LICENSE). No warranty: this tool writes sudoers rules, read it before you run it.
