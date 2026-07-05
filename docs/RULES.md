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
