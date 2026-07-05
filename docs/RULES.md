# Rules reference

Task/rule catalogs live in `src/rules/`. This doc explains the ones that
aren't self-evidently "delete this cache dir" — starting with `badger
optimize`, whose tasks run commands rather than delete anything.

## `badger optimize` (`src/rules/optimize.rs`)

Every task below is honest, reversible-ish system maintenance: nothing here
tunes the kernel or touches boot configuration. Pre-checked tasks run
automatically under `--yes` or the TUI's defaults; opt-in tasks require
explicit selection every time.

| Task | Pre-checked? | Sudo? | What it runs | Why |
|---|---|---|---|---|
| `optimize.fstrim` | Yes | Yes | `fstrim -av` | Discards unused SSD blocks. Most Arch installs already run this weekly via `fstrim.timer`; this is a manual top-up, not a replacement. |
| `optimize.reset_failed` | Yes | System scope only | `systemctl reset-failed` + `systemctl --user reset-failed` | Clears failed-unit counters. Purely cosmetic — never restarts or stops anything. |
| `optimize.font_cache` | Yes | No | `fc-cache -f` | Rescans installed fonts. |
| `optimize.desktop_db` | Yes | No | `update-desktop-database`, `gtk-update-icon-cache -f -t ~/.local/share/icons/hicolor`, `update-mime-database ~/.local/share/mime` (each only if the binary is installed; the icon/MIME sub-commands additionally require their target directory to already exist) | Keeps launchers, icons, and file-type associations in sync after installing/removing desktop apps. |
| `optimize.pacman_files` | No (opt-in) | Yes | `pacman -Fy` | Downloads pacman's full file-list database. Opt-in because it's a sizeable download most people never need. |
| `optimize.mirrors` | No (opt-in) | Yes | Whichever of `cachyos-rate-mirrors` / `rate-mirrors` / `reflector` is installed (in that preference order), or the tool pinned by `optimize.mirror_tool` in config | Re-ranks pacman's mirror list for speed. Opt-in because it rewrites `/etc/pacman.d/mirrorlist` and takes a while. Set `optimize.mirror_tool = "off"` to hide the task entirely; `"auto"` (the default) picks by preference order above. |
| `optimize.updatedb` | Yes | Yes | `updatedb` | Refreshes the mlocate/plocate database `locate` searches. |

### Deliberate exclusions

Not tasks now, and not planned for a later phase either:

- **`mkinitcpio -P`** (regenerate initramfs) — destructive if it goes wrong,
  with no meaningful "preview"; a kernel/microcode update already triggers it
  via pacman's own hooks. Running it opportunistically adds risk with no
  corresponding benefit.
- **sysctl tuning** — irreversible within a `badger` session, highly
  environment-specific (what's "optimal" depends on hardware and workload),
  and not "maintenance" in the sense every other task here is: it's a
  configuration change, not cleanup.
- **RAM-booster / "free the cache" scripts** (e.g. dropping the page cache) —
  not a real optimization. The kernel already reclaims page cache on demand;
  forcing it early just causes extra disk I/O the next time that data is
  needed, with no lasting benefit.

## Snapshot rules (`src/rules/snapshots.rs`)

Both rules are **Risky**, require sudo, and only appear when `snapper` is
installed and `snapshots.manage` (config, default `true`) is `true`. A Risky
selection makes badger's TUI demand you type the number of Risky items
selected before it will proceed — plain "y" is not accepted.

| Rule | What it runs |
|---|---|
| `snapshots.snapper_cleanup` | `snapper -c <config> cleanup number`, once per snapper config — snapper's own retention algorithm, respecting each config's own settings. This is the recommended way to reclaim snapshot space. |
| `snapshots.snapper_manual` | `snapper -c <config> delete <numbers...>` for exactly the snapshots you select. |

### Manual delete: what's excluded

`snapshots.snapper_manual` never offers these for deletion:

- **Snapshot 0** — snapper's "current system" pseudo-snapshot, not a real
  snapshot.
- **The booted snapshot** — read from `/proc/cmdline`.
- **The current default subvolume snapshot** — read from `btrfs subvolume
  get-default /`.

Both of the last two are protected if found; either one being unreadable
doesn't stop the other from protecting its snapshot.

**If badger can't identify the booted snapshot at all** (neither
`/proc/cmdline` nor `btrfs subvolume get-default` resolves a snapshot
number), it refuses to offer *any* manual per-snapshot deletion — you'll see
a skip note explaining why. The cleanup rule above still works in that case,
since it never targets a specific snapshot number.

**Pre/post pairs must be selected together.** If you select a "pre" snapshot
without its paired "post" (or vice versa), that whole snapper config's
deletion is refused and nothing is deleted for it — a note explains which
snapshot caused the refusal. Other configs you also selected snapshots from
are unaffected.

### limine-snapper-sync guidance

Both rules check whether `limine-snapper-sync` is installed:

- **Active** — boot entries re-sync automatically after cleanup/deletion, no
  action needed.
- **Installed but inactive** — a visible warning tells you to run it manually
  afterwards so boot entries stay in sync.
- **Not installed** — no mention at all.

### Config: `snapshots.manage`

Set `snapshots.manage = false` to hide both snapshot rules entirely (default
`true`).

### VM verification pending

**Booted-snapshot exclusion has not yet been verified on a real
btrfs+snapper+limine machine or VM.** The logic is unit-tested against faked
`/proc/cmdline` and `btrfs` output, but nobody has yet confirmed it correctly
identifies the booted snapshot on a live system. Treat manual snapshot
deletion with extra care until that verification happens.

## Old snap revisions (`src/rules/snap.rs`)

`snap.old_revisions` is **Risky** and requires sudo. It looks at `snap list
--all`, which lists one row per (snap, revision); a row is a candidate only
when its Notes column contains the exact token `disabled` — meaning snapd
has superseded that revision with a newer one but kept it around so `snap
revert` can roll back to it.

Each selected candidate runs its own `snap remove <name> --revision <rev>`.
Removing an old revision frees its disk space but gives up the ability to
`snap revert` back to it — that specific rollback point is gone for good.

## Experimental: orphaned app leftovers (`src/rules/leftovers.rs`)

`leftovers.orphan_configs` only exists when badger is run as `badger clean
--experimental`. It guesses at directories under `~/.config`,
`~/.local/share`, and `~/.cache` that look like they belong to an app that's
since been uninstalled — this is inherently a heuristic (there's no reliable
way to *prove* a directory belongs to nothing), so **misidentification is
possible**. Every candidate is labeled `(experimental guess)`, and every one
still goes through badger's normal deletion safety path (`validate_deletable`
+ whitelist) on top of the five conditions below.

A top-level directory becomes a candidate only if **all five** of these hold:

1. **No installed-package match.** Checked against `pacman -Qq` and (if
   flatpak is present) `flatpak list`. A directory name matches an installed
   package if it's an exact match, or a substring match in either direction —
   but only when the shorter of the two names is at least 3 characters (so a
   short package name like `bc` can't "own" a directory like `abc`). If
   `pacman -Qq` itself fails or errors, badger has zero package knowledge and
   fails closed: it offers **zero** candidates for the entire run, rather than
   guessing.
2. **No reference in an installed `.desktop` file.** Badger scans top-level
   `.desktop` files under `~/.local/share/applications` and
   `/usr/share/applications` for an `Exec=` or `Name=` line that mentions the
   directory's name (case-insensitively). A name shorter than 3 characters is
   too ambiguous to search reliably, so it's treated as referenced (fails
   closed — never offered) regardless of what's actually on disk.
3. **Not on the keep-list.** Hidden (dot-prefixed) directories, a directory
   literally named `Trash`, anything starting with `kde` or `plasma`
   (case-insensitive), and this curated list of shared-infrastructure names
   are never candidates regardless of package or desktop-file evidence:
   `gtk-2.0`, `gtk-3.0`, `gtk-4.0`, `dconf`, `pulse`, `systemd`, `fontconfig`,
   `autostart`, `applications`, `icons`, `themes`, `fonts`, `mime`, `nvim`,
   `trash`, `badger`, `pipewire`, `wireplumber`.
4. **Old enough.** The directory's mtime must be older than
   `clean.orphan_min_age_days` (config, default **180** days). If the mtime
   can't be read, it fails closed — not a candidate.
5. **Not in use.** No running process may have the directory as its cwd or
   executable (checked live via `/proc`).

Only top-level directories are ever scanned — files, symlinks, and anything
nested inside a top-level directory are never candidates on their own.
