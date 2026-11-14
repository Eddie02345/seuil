# Decision 002: Linux OAuth Callback for Samsung Sign-In

## Status
Accepted (2026-11-14)

## Context
Samsung's PC SDK returns the OAuth authorization code through a custom
`ms-app://` URI. Linux browsers have no handler for that scheme. Firefox and
Zen block the redirect with "Prevented navigation ... unknown protocol", and
Chromium depends on `xdg-open` and the desktop MIME association. Before this
change `seuil setup` opened the browser and then waited for a URL to be pasted
from the address bar, which the browser never showed for the blocked redirect.
Setup appeared to hang on the sign-in spinner.

The Samsung callback also appends a second `state=new` marker after the
encrypted `state` value, so a parser that rejects duplicate query parameters
could not consume a URL copied from the browser console.

## Decision
1. Register a temporary desktop entry at
   `~/.local/share/applications/seuil-auth.desktop` with
   `Exec=<current_exe> auth-callback %u`, `MimeType=x-scheme-handler/ms-app;`,
   and `NoDisplay=true`. Register it with
   `xdg-mime default seuil-auth.desktop x-scheme-handler/ms-app` and refresh
   the cache with `update-desktop-database`.
2. Add the hidden `seuil auth-callback <URL>` subcommand. It forwards the
   received URL over a Unix domain socket and exits.
3. Bind the socket at `$XDG_RUNTIME_DIR/seuil-auth.sock`, falling back to
   `<config>/seuil/auth.sock`. `MCFDS_AUTH_SOCKET` overrides both.
4. Wait for the socket, stdin, or Ctrl+C with `tokio::select!`. Keep the paste
   path because the browser cannot always launch the temporary handler.
5. Normalize pasted input by stripping whitespace and ASCII or curly quotes,
   and by extracting the `ms-app://` URL from a full browser console line.
6. When parsing the callback, try every non-empty `state` value until one
   decrypts. Take the first non-empty value for the other fields.
7. Use one shared stdin line reader for the OAuth wait and the later device
   prompts.

## Rationale

### Why a temporary desktop handler?
A permanent handler would claim `ms-app://` for Seuil after setup, when the
socket no longer exists. The temporary entry is installed only while setup
waits, then removed. The previous handler is restored on cleanup.

### Why keep the paste fallback?
Firefox-based browsers can cache protocol handler state or block unknown
schemes outright. The blocked navigation still logs the complete
`ms-app://` URL in the DevTools console, so the paste path is the reliable
fallback. Chromium usually delegates to `xdg-open` and can launch the handler
directly.

### Why one shared stdin reader?
The first implementation spawned a blocking `read_line` thread while waiting
for the socket. When the socket won, that thread stayed blocked on stdin and
stole the first line typed into the phone prompt, which made the user press
Enter twice. A single reader that owns stdin for the process and feeds a
channel removes the race. The auth wait and the device prompts read from the
same channel.

## Implementation
- `daemon/src/auth/browser.rs`: socket binding, desktop entry lifecycle,
  handler forwarding, cleanup and previous-handler restoration.
- `daemon/src/auth/mod.rs`: callback waiting, paste normalization, duplicate
  `state` handling, shared stdin reader.
- `daemon/src/main.rs`: hidden `auth-callback` subcommand.
- `daemon/src/setup.rs`: async device prompt using the shared reader.

## Verification
- Unit tests cover quoted and whitespace-wrapped URLs, full Firefox console
  lines, duplicate callback fields, and a valid encrypted callback carrying
  `state=new`.
- `gio open 'ms-app://...'` launched the hidden callback and delivered the URL
  over the socket.
- `cargo test --locked` passes 58 tests.
- `cargo build --release --locked` succeeds as `seuil v1.0.1`.

## Consequences
- `seuil setup` no longer waits on a browser page that cannot complete.
- The desktop entry and socket exist only for the duration of the callback
  wait. Ctrl+C also cleans them up.
- Browsers that block the scheme still require one copy and paste from the
  console, as documented in the setup prompt.
- After cleanup, the previous `ms-app://` handler is restored if one existed.
