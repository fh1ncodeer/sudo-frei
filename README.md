# sudo-frei

Zeitlich begrenztes `sudo` ohne Passwort auf den eigenen Linux-Rechnern, von einem Rechner aus per SSH gesteuert. Eine kleine TUI zeigt alle Freigaben mit Countdown und den Zustand des SSH-Agenten.

Gedacht für Momente, in denen man eine Weile Admin-Arbeit erledigt (oder ein Agent sie erledigt) und nicht bei jedem Befehl das Passwort tippen will. Danach soll garantiert wieder alles wie vorher sein.

```
sudo-frei grant server 30     # 30 Minuten sudo ohne Passwort auf "server"
sudo-frei status              # alle Rechner aus der Konfiguration
sudo-frei revoke server       # vorzeitig beenden
sudo-frei-tui                 # dasselbe als Oberfläche
```

## Wie es funktioniert

Auf dem Zielrechner wird nichts installiert. `sudo-frei` schickt seinen Code bei jedem Aufruf per SSH mit. Eine Freigabe legt in **einem** sudo-Aufruf drei Dinge an:

1. **Regel:** `/etc/sudoers.d/zz-sudo-frei` mit `USER ALL=(ALL:ALL) NOPASSWD: ALL`. Sie wird vorher mit `visudo -c` geprüft und dann atomar umbenannt.
2. **Timer:** ein einmaliger systemd-Timer mit fester Ablaufzeit in UTC. Er löscht Regel, Markierung und den sudo-Zeitstempel des Benutzers.
3. **Neustart-Aufräumen:** `/etc/tmpfiles.d/sudo-frei.conf` löscht Regel und Markierung beim Booten, falls der Timer verloren geht.

Dazu kommt `/run/sudo-frei-ende` mit der Ablaufzeit, lesbar ohne Rechte. Daran erkennt `status` den Zustand.

| Fall | Verhalten |
|---|---|
| Zeit läuft ab | Timer löscht die Regel, auf etwa 1 s genau |
| Ruhezustand über die Ablaufzeit | wird beim Aufwachen gelöscht |
| Neustart | wird beim Booten gelöscht |
| Verbindung reißt ab, Ctrl-C | der root-Teil ignoriert HUP/INT/TERM und läuft zu Ende |
| erneute Freigabe scheitert | die alte bleibt samt Timer bestehen |
| `revoke` | löscht zuerst die Regel, dann die Timer |
| Regel ohne Timer | `status` meldet **verwaist** statt „aus“ |

## Was man in Kauf nimmt

Während einer Freigabe ist der Benutzer faktisch root, ohne Rückfrage. Das gilt für jeden Prozess, der als dieser Benutzer läuft, und für jeden, der den SSH-Schlüssel benutzen kann. Fenster daher kurz halten, besonders auf öffentlich erreichbaren Servern.

## Voraussetzungen

- **Steuerrechner:** bash, ssh, python3 ≥ 3.11 (für `tomllib`), für die TUI Rust ≥ 1.85.
- **Zielrechner:** Linux mit systemd und sudo, Anmeldung per SSH als normaler Benutzer mit sudo-Recht.
- **Getestet:** Arch (systemd 262, sudo 1.9.17) und Debian 13 (systemd 257, sudo 1.9.16).
- **Ubuntu ab 25.10 mit `sudo-rs`:** gedacht, aber ungetestet.
- **Raspberry Pi OS:** bringt `/etc/sudoers.d/010_pi-nopasswd` mit, sudo ist dort also dauerhaft ohne Passwort. `sudo-frei` ist dort erst sinnvoll, wenn diese Datei entfernt ist.

## Installation

```
ln -s "$PWD/scripts/sudo-frei" ~/.local/bin/sudo-frei
cargo install --path .            # installiert sudo-frei-tui
mkdir -p ~/.config/sudo-frei
cp config.example.toml ~/.config/sudo-frei/config.toml   # Rechner eintragen
```

## Konfiguration

`~/.config/sudo-frei/config.toml`, siehe `config.example.toml`. Das Skript liest daraus nur `hosts`, die TUI zusätzlich `presets`, `default_minutes`, `refresh_seconds` und `script`.

## TUI

| Taste | |
|---|---|
| ↑↓ | Rechner wählen |
| g | freigeben (Minuten tippen oder ←→ Vorschläge) |
| r | widerrufen |
| a | SSH-Schlüssel laden (`ssh-add`) |
| x | Agent leeren |
| u | neu prüfen |
| q | beenden |

Die Spalte **SSH-Schlüssel** zeigt pro Rechner, ob der Schlüssel aus `ssh -G HOST` im Agenten geladen ist. Für Passwort- und Passphrase-Abfragen gibt die TUI das Terminal an `sudo-frei` bzw. `ssh-add` ab.

## Tests

```
scripts/sudo-frei-test    # root-Ablauf in einem Testordner, ohne sudo/ssh
cargo test
```
