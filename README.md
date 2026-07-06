# badger

A terminal system cleaner for CachyOS and other Arch-based distros, inspired
by [Mole](https://github.com/tw93/Mole) for macOS. `badger` finds reclaimable
disk space, unused packages, and stale system state, shows you exactly what it
found, and only touches disk when you say so.

Six commands cover the day-to-day upkeep of an Arch system: caches, orphaned
packages, disk-usage exploration, mirror/system tuning, and a live status
view.

## Install

**AUR (coming soon — not published yet):**

```sh
paru -S badger-cleaner       # builds from source
paru -S badger-cleaner-bin   # prebuilt binary
```

**One-line installer (coming soon — available after the first tagged release):**

```sh
curl -fsSL https://raw.githubusercontent.com/GabrielBhh/badger/main/packaging/install.sh | sh
```

**From source, right now:**

```sh
cargo install --git https://github.com/GabrielBhh/badger --locked
```

The binary is called `badger` regardless of which package you install.

## Commands

| Command | What it does |
|---|---|
| `badger clean` | Clears user/dev caches, package cache, journal logs, and (with `--experimental`) orphaned app leftovers |
| `badger purge` | More aggressive cleanup of reclaimable space, including old build/dev artifacts (skips anything touched recently) |
| `badger uninstall` | Finds and removes packages nothing depends on, plus their leftover config/cache directories |
| `badger analyze [path]` | Interactive disk-usage explorer for a directory (defaults to your home) — delete straight to trash or permanently |
| `badger status` | One-shot or live dashboard of disk, memory, CPU, and background task health |
| `badger optimize` | Runs safe system maintenance: SSD trim, mirror ranking, font/icon/locate database refresh, etc. |

Every command also supports `badger history` (review past runs) and `badger
whitelist` (protect paths from ever being offered).

Run `badger <command> --help` for the full flag list, or see the generated
man page (`man badger`, once packaged).

## The safety story

badger deletes things on your behalf, so it's built to be conservative:

- **Dry-run by default.** Without `--yes` (or on `clean`/`purge`/`optimize`),
  badger only shows you what it *would* do — nothing is deleted or run until
  you explicitly confirm.
- **Whitelist.** Any path or pattern you add to `badger whitelist` is greyed
  out and skipped everywhere, permanently, until you remove it.
- **Risk tiers.** Every candidate is tagged Safe, Moderate, or Risky.
  Moderate selections are called out explicitly before you confirm; Risky
  selections (rare, and none are pre-checked by default) require you to type
  the exact number of items you're about to affect before badger proceeds.
- **Trash, not `rm`.** `badger analyze` deletes to the freedesktop trash by
  default; permanently deleting bypasses the trash only if you type the word
  `delete` to confirm.
- **Journal + history.** Every run is logged; `badger history` shows what was
  done, when, and in which run, so nothing is a mystery after the fact.
- **Path validation.** Every deletion is checked against ownership, mount
  boundaries, and a protected-paths list before it's allowed to happen at all
  — this runs even if a rule itself has a bug.

**Snapshot caveat:** if `badger optimize`/`clean` touches Btrfs snapshots
(via `snapper`), the logic that identifies your *currently booted* snapshot
(to make sure it's never a deletion candidate) has been unit-tested against
simulated system state but has **not yet been verified on a real
btrfs+snapper+bootloader machine**. Treat snapshot-related cleanup with extra
care until that verification happens — see `docs/RULES.md`.

## Configuration

badger reads `~/.config/badger/config.toml` (or `$XDG_CONFIG_HOME/badger/config.toml`).
Every key is optional — anything you don't set uses the default below.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `[clean]` | `paccache_keep` | `2` | Package-cache versions to keep per package |
| `[clean]` | `journal_max_size` | `"300M"` | Target size passed to `journalctl --vacuum-size` |
| `[clean]` | `trash_older_than_days` | `30` | Age before a trashed item is a cleanup candidate |
| `[clean]` | `orphan_min_age_days` | `180` | Minimum age for an orphaned-config guess (`--experimental` only) |
| `[purge]` | `roots` | `["~/dev", "~/projects", "~/claude_apps"]` | Directories `badger purge` looks for build/dev artifacts under |
| `[purge]` | `recent_days` | `7` | Artifacts touched within this many days are never pre-checked |
| `[snapshots]` | `manage` | `true` | Whether badger offers snapper snapshot cleanup at all |
| `[optimize]` | `mirror_tool` | `"auto"` | Which mirror-ranking tool to use, or `"off"` to disable that task |
| `[ui]` | `mascot` | `true` | Show the badger mascot in the TUI |

Command-line flags always win over the config file: `--dry-run`, `--json`,
and `--debug` are global; run `badger --help` for the rest.

## More detail

Full rule-by-rule reference (what each cleanup task does, exclusions, and
known caveats) lives in [`docs/RULES.md`](docs/RULES.md).
