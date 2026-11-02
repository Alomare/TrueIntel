# True Intel

A Helldivers 2 Lua mod for [Bingus Shared Loader](https://github.com/CowboyBingus/BingusSharedLoader) that reveals what the game hides or misstates, in the game's own menus. It starts with the real numbers behind the Armory's armor passive descriptions: it corrects the ones the game misstates and reveals the ones it hides.

## Features

Each line below replaces the game's own line in the Armory's passive panel, in the same style and colours:

| Passive | The game says | True Intel |
| --- | --- | --- |
| GUNSLINGER | Increases sidearms reload speed by 40%. | Increases sidearms reload speed by **60%**. |
| EXTRA PADDING | Provides a higher armor rating. | Provides **+50** armor rating. |
| CONCUSSIVE PADDING, REINFORCED | Provides a higher armor rating. | Provides **+30** armor rating. |
| UNFLINCHING, SUPPLEMENTAL ADRENALINE, BLUNT-FORCE MITIGATION | Provides a higher armor rating. | Provides **+25** armor rating. |
| PEAK PHYSIQUE, TRUE GRIT | (Slightly) increases weapon ergonomics to reduce drag on weapon movement. | Increases weapon ergonomics by **30** (**20**) (max 100) to reduce weapon drag. |
| SUPPLEMENTAL ADRENALINE | When the wearer takes damage, they regain some stamina. | When the wearer takes damage, they regain **2%** stamina per **1%** of health lost. |
| ROCK-SOLID, BLUNT-FORCE MITIGATION | Bearer is more resistant to being knocked prone. | Reduces knockdown force against the bearer by **30%**. |
| OXYGENATOR | Increases the wearer's walking and running speed. | Increases the wearer's jogging and sprinting speed by **10%**. |

- The armor rating the Armory shows already includes the passive's share; True Intel says how much of it the passive provides.
- Every other number in the armor passive descriptions is already exact. The other reload, ammo and sidearm lines match what their passives apply today; if a game update makes one differ, True Intel shows its real number.
- The numbers are read from the game itself, so a changed value shows as changed.
- Display only: nothing the game uses changes, so it is safe in any lobby, and players without the mod see the game's texts.
- In every game language: the lines follow the game's Text Language.

## Installation

1. Install [Bingus Shared Loader](https://www.nexusmods.com/helldivers2/mods/16292) (v17 or newer) and [HD2Runtime](https://github.com/SkyeShade/HD2Runtime/releases) (0.31.2 or newer), which holds the mod's texts.
2. Install the ZIP from [Releases](https://github.com/Alomare/TrueIntel/releases) with [HD2 Arsenal](https://www.nexusmods.com/helldivers2/mods/4664) (or HD2 Mod Manager) and deploy. Keep Bingus Shared Loader last in the mod order, so it loads first.

The Armory's panel builds its text when the item you look at changes. The verdict is the first line of `%LOCALAPPDATA%\CowboyBingus\Helldivers2\Logs\TrueIntel_STATUS.log`.

## Technical Details

- **Where the numbers come from.** The Armory's description lines are a passive record's modifier rows that carry a text id. Each value's meaning comes from the game code that reads its key, found in a game.dll dump:
  - GUNSLINGER's reload row is a description-only copy (no code reads its key); the effect is the passive's spawn-time stat row, ×1.6.
  - The Armory's armor rating is 100 + (armor − 1) × 50, with the passive's value added to the armor, so the passive provides value × 50 of it.
  - Ergonomics adds the value to the weapon's ergonomics, capped at 100.
  - Stamina on damage adds the fraction of health lost × 2 to the stamina bar.
  - Knockdown compares the hit's force × 0.7 with the threshold.
  - The speed rows scale the jog and sprint tiers by 1.1.
- **The swap.** A line replaces one row's text id with a text of the mod's own. The row's key, type and value stay untouched, so every game system reads exactly what it did. A row is changed only while it holds the game's own text id: another mod's text is left alone, and the game's ids go back when the mod stops.
- **Texts.** The lines are registered in SkyeShade's [HD2Runtime](https://github.com/SkyeShade/HD2Runtime) text table, which every mod using it shares, in all 15 game languages at once, so the game shows its current language's text. Numbers use each language's own format, and lines without a number in the game's text use the game's own value formatting. `locales/en.lua` is the English source and `locales/<tag>.lua` the bundled translations, resolved by CowboyBingus' `src/bingus_text.lua` (translation packs for it apply too); the build places both ahead of the script.
- **Finding the game's code.** The passive tables, the rows' layout and the Armory's armor scale come from code signatures generated in one block by `research/signatures.py` from a game.dll dump. At startup each is tried at the known build's address, else game.dll is searched; a signature must match exactly once and shared values must agree. Without the armor scale only the armor lines stay the game's; without the rest the mod stays off.
- **The panel's room.** `research/lines.py` builds the lines from the game's passive records and checks every changed passive in every language against the game's own longest passive in that language (and the panel's text buffers). [research/lines.md](research/lines.md) lists every row and its verdict.
- **Memory access.** Reads and writes go through `ReadProcessMemory` / `WriteProcessMemory` on the game's own process, declared under the mod's own FFI names (`ti_ReadProcessMemory`, bound to the export) so another mod's declarations of those functions can't change how they are called: the lines are made once, the rows are checked every 10 seconds and the texts every quarter second (a language change drops them; they are registered again).
- **Tests.** `tests/test_release.py` runs the built entry under LuaJIT against a game.dll dump (not included), with the game's real passive records and HD2Runtime's text table simulated.

How it works in the game's code: [RESEARCH.md](RESEARCH.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Release notes: [CHANGELOG.md](CHANGELOG.md).

## Credits

- Built on [Bingus Shared Loader](https://github.com/CowboyBingus/BingusSharedLoader) by CowboyBingus, whose `bingus_text.lua` provides the translations.
- Uses code / research from HD2Runtime by SkyeShade, https://github.com/SkyeShade/HD2Runtime: its text table holds the mod's lines, and its armor passive research agrees on GUNSLINGER's ×1.6.
- Passive records from [FileDiver](https://github.com/xypwn/filediver); armor ratings checked against the [Helldivers 2 wiki](https://helldivers.wiki.gg).
- Developed with Claude Opus 5.5 and the [HD2 Lua Mod Skill](https://github.com/MrChengl11/hd2-lua-mod-skill).

## License

Copyright (c) 2026 Alomare. Licensed under the [MIT License](LICENSE). `src/bingus_text.lua` is CowboyBingus's, under the Zero-Clause BSD license.
