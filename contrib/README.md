# Service templates for `pondline-mailbox`

These templates run `pondline-mailbox serve` as a supervised background service
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

## Linux (`systemd`)

Note: the Linux branch of `scripts/release.sh` requires a build host with
OTP 29 linked against OpenSSL >= 3.5 plus `patchelf`, and should pass
`make release-smoke` on the target distribution before production use
(see `docs/adr/003-packaging.md`).

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
