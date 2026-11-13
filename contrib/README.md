# Service templates for `pondline` and `pondline-mailbox`

For the client daemon (`pondline daemon`), run `pondline init --stdin` once and
then install, inspect, or remove the per-user background service directly:

```bash
pondline service install            # writes and starts launchd / systemd --user
pondline service status
pondline service uninstall
```

The reference client templates live in `contrib/launchd/io.pondline.daemon.plist`
and `contrib/systemd/pondline.service`.

The templates below run `pondline-mailbox serve` as a supervised background service
over Tor. Both templates keep `--tor-state` on a short directory path because
Arti opens a Unix domain socket (`connect.sock`) inside that directory, and
`AF_UNIX` paths are bounded to roughly 100 bytes on macOS and 108 bytes on
Linux.

## macOS (`launchd`)

1. Install the release into `~/.local`:

   ```bash
   make install
   mkdir -p -m 0700 ~/.pondline-mailbox ~/.pondline-mailbox/tor
   ```

2. Copy `contrib/launchd/io.pondline.mailbox.plist` to
   `~/Library/LaunchAgents/io.pondline.mailbox.plist`, replace `/Users/YOU`
   with your home directory path, and load it:

   ```bash
   launchctl load ~/Library/LaunchAgents/io.pondline.mailbox.plist
   ```

3. Once Tor finishes bootstrapping, `serve` writes the hosted `.onion:80`
   endpoint to `~/.pondline-mailbox/tor/onion` and `stdout.log`. Mint a
   copy-pasteable `plg1...` grant token for a user while the server stays live:

   ```bash
   pondline-mailbox grant \
     --db ~/.pondline-mailbox/mailbox.db \
     --tor-state ~/.pondline-mailbox/tor \
     --queues 100 \
     --token
   ```

4. Check live queue, byte and grant usage at any time:

   ```bash
   pondline-mailbox status \
     --db ~/.pondline-mailbox/mailbox.db \
     --tor-state ~/.pondline-mailbox/tor
   ```

## Linux (`systemd` user service with `linger`)

On a rootless host with user lingering enabled (`loginctl enable-linger $USER`),
install under `~/.local` and run `pondline-mailbox` as a user service:

1. Install the latest `linux-x86_64` release (or unpack a built `dist/` archive):

   ```bash
   curl -fsSL https://github.com/Roasbeef/pondline/releases/latest/download/install.sh | bash
   mkdir -p -m 0700 ~/.local/state/pondline-mb ~/.local/state/pondline-mb/tor
   mkdir -p ~/.config/systemd/user
   cp contrib/systemd/pondline-mailbox-user.service ~/.config/systemd/user/pondline-mailbox.service
   systemctl --user daemon-reload
   systemctl --user enable --now pondline-mailbox.service
   ```

2. Mint a `plg1...` grant token or update in place (`pondline-update` switches
   `~/.local/lib/pondline/current` atomically without deleting the live tree):

   ```bash
   ~/.local/bin/pondline-mailbox grant \
     --db ~/.local/state/pondline-mb/mailbox.db \
     --tor-state ~/.local/state/pondline-mb/tor \
     --queues 100 \
     --token

   ~/.local/bin/pondline-update --restart-user-service
   ```

## Linux (`systemd` system service)

1. Install the release under `/usr/local` and create the service user and
   private state directory:

   ```bash
   sudo PREFIX=/usr/local ./install.sh
   sudo useradd --system --home-dir /var/lib/pondline-mb --shell /usr/sbin/nologin pondline
   sudo install -d -m 0700 -o pondline -g pondline /var/lib/pondline-mb /var/lib/pondline-mb/tor
   ```

2. Install and enable the unit:

   ```bash
   sudo cp contrib/systemd/pondline-mailbox.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now pondline-mailbox.service
   ```

3. Mint a `plg1...` grant token or inspect server status:

   ```bash
   sudo -u pondline /usr/local/bin/pondline-mailbox grant \
     --db /var/lib/pondline-mb/mailbox.db \
     --tor-state /var/lib/pondline-mb/tor \
     --queues 100 \
     --token

   sudo -u pondline /usr/local/bin/pondline-mailbox status \
     --db /var/lib/pondline-mb/mailbox.db \
     --tor-state /var/lib/pondline-mb/tor \
     --json
   ```
