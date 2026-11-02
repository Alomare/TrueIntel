# True Intel: how it works in the game's code

True Intel shows what the game hides or misstates, in the game's own menus: today, the real numbers behind the Armory's armor passive descriptions. It changes display data only (a row's text id), never a value a game system reads. Addresses are game.dll RVAs for build 25480438; the mod finds every one by code signature (`research/signatures.py`), so it survives updates that move the code.

## The passive tables

A global customization manager holds every armor passive. `PassiveValue(passive id, key)` (0x11DA090) reads it:

- manager `[0x33264F8]`: +0x30 an inline u32 table, passive id -> record index (-1 = no record); +0x20 the array of record pointers.
- A record (56 bytes): +0x10 its modifier rows {pointer, count at +0x18}, 16 bytes each: +0 key (a hash), +4 type, +8 value (float), +0xC text id.
- Row types: 1 Add, 2 Multiply; the other types (Set, Time) replace the base value. PassiveValue returns (base + every Add) x every Multiply.
- The record's stat rows {pointer +0x20, count +0x28}, 12 bytes each {stat, add, mul}, are applied once at spawn by 0x11DA190, starting from the armor kit's passive id (kit +0x1C). Stat 20 (Count) is skipped.

The Armory's description lines are the record's modifier rows that carry a text id. In the text, `#BONUS` is the row's value: Multiply as |1 - v| x 100 %, Set and Add as the integer, Time in seconds (the English templates are `#PERCENT%` and `#SECONDSs`).

## What the values really do

The meaning of each value comes from the code that reads its key. [research/lines.md](research/lines.md) lists every vanilla row with its verdict.

**Description-only rows.** No game code reads these keys: `B4F88129`, `CC530B21`, `33C9C713`, `35F17BEC`, `AD5289FE`, `22035F3C` (reload, ammo and sidearm lines). They exist only for the text; the effect is the passive's stat row. GUNSLINGER's row says 40% (x1.4) but its stat 15 is x1.6, so sidearm reload is 60% faster. Every other copy matches its stat row in this build (REINFORCED EPAULETTES, SIEGE-READY's two, TRUE GRIT, GUNSLINGER's draw and recoil, CONCUSSIVE PADDING, HAZMAT's recoil).

**Values hidden behind vague text:**

| Key | Type | Read by | Meaning | Passives |
| --- | --- | --- | --- | --- |
| `AFAE3B47` armor | Add | 0x1915EB0 (the Armory's stats) | ARMOR RATING = 100 + (armor - 1) x 50, where armor = PassiveValue(kit passive, kit armor, AFAE3B47): the row is worth value x 50 of the rating shown, which already includes it | EXTRA PADDING +50; CONCUSSIVE PADDING, REINFORCED +30; UNFLINCHING, SUPPLEMENTAL ADRENALINE, BLUNT-FORCE MITIGATION +25 |
| `C8CCB6FA` ergonomics | Add | 0x779250 | the weapon's ergonomics + value, capped at 100; then t = ergonomics / 100 gives two movement factors, 1 + 0.5 t and 1 + 19 t² | PEAK PHYSIQUE +30, TRUE GRIT +20 |
| `A189ADB6` stamina on damage | Add 2 | 0x9435F0 | stamina (a 0-1 fraction at `[0x3326D20] + 0x547854 + i x 0x78`) += (health fraction before the hit - after) x value, capped at full: 2% stamina per 1% of health lost | SUPPLEMENTAL ADRENALINE |
| `11A3C04C` knockdown | Multiply 0.7 | 0x93FD50 | knocked prone when the threshold (+0x12DC) <= the hit's force x value: 30% less knockdown force (0x87A6E0 scales a float the same way) | ROCK-SOLID, BLUNT-FORCE MITIGATION |
| `CD79A687`, `F6D67313` speed | Multiply 1.1 | 0x9E94C0 | the locomotion tiers' speeds x their key's value: jog and sprint +10%; the walk tier has no key (the text says "walking and running") | OXYGENATOR |
| `CB814D05` survival | Multiply 1.5 | 0xB71860 | survives when value - 1 >= a uniform roll: the stated 50% is exact | DEMOCRACY PROTECTS |

The same Armory function gives SPEED = value x 5 x 100 and STAMINA REGEN = (2 - value) x 100. The armor scale 50.0 is a float global in its code. The armor ratings agree with the community wiki: light / medium / heavy 50 / 100 / 150, with EXTRA PADDING 100 / 150 / 200, the 0.5 passives 75 / 125 / 175, CONCUSSIVE PADDING, REINFORCED 180.

Every row whose text shows `#BONUS` reads its own value (resistances, throw range, limb health, stims, radar scans...), and "Prevents all damage from bleeding" is x0: those lines are exact.

**Rows not explained yet:**
- `8933E7F4` (no text; x0.05 on ELECTRICAL CONDUIT, ACCLIMATED, ADRENO-DEFIBRILLATOR, x0.06 on DESERT STORMER): read at 0x87A5B9, a small accessor like 0x87A6E0. HD2Runtime calls it an element-2 status amount (likely arc stun buildup).
- `0DFF0E42` (no text; Set 1 on PEAK PHYSIQUE and ROCK-SOLID): selects state 0x7DCD5820 instead of 0x0399532A in a state machine (0x1147C10).
- UNFLINCHING's stat 11 (x0.05): 0x607ED0 scales an integer quantity.

**The game's translations misstate some lines too:** Russian TRUE GRIT says primary weapons ("основного оружия") and Spain Spanish secondary weapons ("armas secundarias") instead of support weapons; Korean SIEGE-READY's ammo line says primary weapons only ("주 무기의") instead of all weapons.

## The Armory's passive panel

- The panel (0x192B980) makes one line per modifier row with a text id (rows with id 0 are skipped), formatted by 0x192BE10 with SIGN / BONUS / COLOR into a 0x200-byte buffer at panel +0x2958, then copied to +0x17A8 for the layout. Lines are separated by `\n`, `<c=#COLOR>` resolves to `<c=ffffe900>`, Time values get one decimal (`2.0s`; `2,0s` in Brazilian Portuguese).
- It rebuilds its text only when its cached offer (+0x27E8) changes (`cmp [rcx+0x27E8], edx; je` at its start): a changed line shows once another item has been shown.
- Reaching it: the UI manager's screen of type 224 (the Armory controller) -> its item browser (+0x7F718) -> detail panel (+0x99D70) -> passive widget (+0x21460).
- Room: three rows of 176 visible characters in all fit in English, 227 overflowed; the game's own longest lines run to 104 characters (ADRENO-DEFIBRILLATOR's) and wrap. Every formatted line must stay under 255 bytes and a passive's lines under 512. `research/lines.py` checks each changed passive in every language against the game's own longest passive in that language.

## The swap

A line replaces one row's text id (+0xC) with a text of the mod's own. The row's key, type and value stay untouched, so every game system reads what it did; the text id is display data only. The passive records are private read-write memory (HD2Runtime's perk editor writes the same rows' values), so no protection change is needed. A row is changed only while it holds the game's own text id (another mod's text is left alone), and the game's ids go back when the mod stops or its texts can't be registered, so no line shows blank.

A textless row can get a line by a text id swap alone (no array repoint), at the cost of panel room. A text-only row (key 0, Set; no attribute lookup asks for key 0) could be appended by repointing a record's rows {pointer, count} to a copy; True Intel does not do this.

## Texts

- The lines live in HD2Runtime's development text module (`handle`, `id_bytes`, `ensure`, `resolves`; `game_text` reads the game's own text, 0.31.2+). One table serves every mod: at most 256 texts, 64 KB and 16 tables a session, so every text is defined before the first `ensure`. A handle id must keep its text, so a number baked into a text goes into its id (`p18_b4f88129_60`). Any mod's `ensure` registers every mod's texts; after a language change the table is registered again.
- A handle takes every game language at once ({default, us, gb, bp, de, es, fr, it, jp, ko, ms, pl, pt, ru, cn, tc}) and the game shows its current language's text. Codes to locale tags: us en, gb en-GB ("armour", as the game writes it), bp pt-BR, ms es-419, jp ja, cn zh-Hans, tc zh-Hant, the others as they are.
- Each language uses the game's own terms and its number format (the game's `#PERCENT` template: `60 %` in German and Spain Spanish, a no-break space in French and Latin American Spanish, `60％` in Japanese). `#BONUS` lines keep the game's own formatting.

## Compatibility

- Helmet Passives Reborn adds 7 passive records (the manager's count becomes 39) and rewrites helmet kits' passive ids. Records are read by id through the index table, so any count works.
- HD2Runtime 0.40.0's armor perk editor (`hd2.passives.perk`) edits modifier values and stat rows. `#BONUS` lines follow it; the stat and armor lines bake their number when made and keep it until the game restarts (a live change is logged).
- Every Bingus Shared Loader addon shares one LuaJIT FFI namespace: a function name keeps its first declaration, and another mod's declaration of `ReadProcessMemory` with other types breaks later callers. True Intel declares kernel32 under its own names bound to the exports (`ti_ReadProcessMemory` with `__asm__("ReadProcessMemory")`, and likewise `ti_GetCurrentProcess`, `ti_GetModuleHandleA`, `ti_WriteProcessMemory`).

## Operations and missions (partly confirmed in game)

Offline research for the next feature: every mission of an operation on the galactic map. The game reveals an operation's missions one at a time, but the client appears to make all of them when the operation is created.

- **The mission board** `[0x347CEE8]`. The selected (hovered) operation's index is at board + 0x17A2A0 (-1 = none, or a joinable lobby is hovered); operation records are at board + 0xF7280, 0x5C bytes each, fewer than 0x6E (110); the getter at 0x6FDE4A reads exactly these.
- **The operation record** (0x5C bytes): +4 operation id, +0xC seed, +0x10 planet (u16), +0x14 campaign id, +0x18 placement node (u8), +0x1C type, +0x20 difficulty (u8), +0x24 race, +0x28 joint operation id, +0x30 war id, +0x34 active, +0x35 sync state, +0x38 settings index (x 0x490 into a static table at 0x32FEF10, first u32 the settings id), +0x3C a list of u32 with its count at +0x44 (u8; not named yet), +0x48 per-mission states (u32 each, count +0x54), +0x55 the missions' row indices (u8 each, at most 3), +0x58 the mission count (u8).
- **Operation/Create** (0x12BF770) sends each new operation to the backend (seed, warId, planetIndex, campaignId, type, difficulty, race, jointOperationId, placementNodeIndex, operationSettingsId) with `missions: [{index, type, state}]`, one entry per mission, read from the record. It is sent once, when the sync byte (+0x35) is 1 (then 3), from the operation-select handler 0x12D18F0, by the host only (`board + 0x1F8078 == [0x347CEF0] + 0xB398`, the local peer).
- **The mission rows** (0x4C bytes at board + 0xF9A10, their count at board + 0xFFC08; 330 fit): +0x00..+0x24 cleared at Mission/Start (live mission data), +0x28 the operation's index, +0x2C an index (x 0x88 into the planet's region table), +0x30 the mission definition's index, +0x34 seed, +0x38 state (0 skipped by the planet markers, 1-2 open, 3 done), +0x3C an id (rows are looked up by {+0x2C, +0x3C} at 0x12D1F90), +0x40 the type sent to the backend, +0x44 the mission's index in the operation (Mission/Start's `missionIndex`, 0x12DC080), +0x48 an index into the record's +0x3C list.
- **The mission definitions:** a static table at 0x3773420 filled at start-up, 0xA2 (162) entries of 0x380 bytes (the loop at 0xFD2A24): +0 the mission id (HD2Runtime's mission catalogue key; entry 0 is `0xC8859069`, Launch ICBM), +8 faction (2 Terminids, 3 Automatons, 4 Illuminate), +0x340 the name text id, +0x344 the description text id. 127 of the 162 names are in the game's English strings; the other 35 are probably dormant or event variants. The names come from the game's own text in the player's language.
- The backend's reply is parsed at 0x105D090 (each `operations[]` entry: id, seed, warId, planetIndex, placementNodeIndex, campaignId, communityTargetId, jointOperationId, regionIndex, isActive, type, difficulty, race, `missions` (0x30 bytes each, parsed at 0x10550C0: index, type, state, participants, missionId), rewards, operationSettingsId).
- **The map:** the presenter stack is at `[0x347CE28]` + 0x4288 (stack at +0x14, depth at +0x28); a top presenter of 15 is the galactic map, 14 the briefing. The map fills one 200-byte mission descriptor for the hovered operation at board + 0x4168D0 (seeds +0 / +4, faction +8, difficulty +9, planet hash +12, mission type (u16) +26): the operation's current mission only.
- **Confirmed in game** (a probe logging every record and row once a second, with the missions then played):
  - The board's records are the operations of the planet being viewed: 30 of them, three for each difficulty 1 to 10 (records 0-2 difficulty 1, ..., 27-29 difficulty 10), with 1, 2 or 3 missions by difficulty. Viewing another planet rewrites them.
  - Every mission row exists, with its final definition, before the operation is chosen. Choosing it gives the record its backend id (+4, 0 before) and changes no row; after a mission its row's state is 3 and the record's state for it too (`{1 3}`).
  - The card's current mission is the row whose seed (+0x34) is the map descriptor's seed (+0): an operation's index-1 mission came first, so the row index is not the order of play.
  - A squad member who isn't the host can't hover operations on the map (only the host steers it).
- **The operation settings** (static, 0x490 bytes per settings index, the record's +0x38, at 0x32FEF10): +0 the settings id, +0x24 the operation's name, +0x28 its long description, +0x2C the description the map's operation card shows (text ids). Index 1 is PEACEKEEPING OPERATION ("Tactically eliminate all obstacles standing in the way of peace.").
- **The card:** the galactic map's operation card shows the operation's name, that description and its impact, nothing about its missions (no count, no names).
- Not settled: what the record's other states mean, and the order of the missions after the first.

## Text widgets (not yet confirmed in this mod)

The game's text labels (Mod Options Menu, One Click Armor Set and Flexible Loadouts use them live): a label holds its text id at +0x110 and up to 14 format arguments {key, type, value} of 24 bytes from +0x118, their count at +0x268 (u8), as the label initializer 0x143AFA0 sets them up. `set_label(w, id)` (0x143BF90) sets the text id; `set_string_arg(w, key, char *)` (0x143C950) adds a string argument (type 1), and the label keeps the string's pointer. The text id 0xC67C7FAF is the template `#COUNT` alone, so `set_label(w, 0xC67C7FAF)` then `set_string_arg(w, 0xAB2A7B35 (COUNT), text)` shows any text without a text table entry. `set_label` returns early when the id is already the label's.

The galactic map's operation card: the UI manager `[0x3326E68]` has an event registry for the map at +25224 = {count (1), owner pointer +8, kind +16 (226)} (Know Your Constellation); the operation frame is at owner + 349072. The card's description label is inside the frame, holding the settings' +0x2C text id.

## Loading screen tips (not yet confirmed in game)

The tips the loading screens show are a list of 82 text ids (the English strings run from "Did you know tips are shown during these transition sequences?" to the seven ministries), in game.dll's data: 18 identical copies in build 25480438, 17 in the read-only section (0x21F0D00, 0x21F5520, ...) and one in the writable data section (0x3317D60). No instruction addresses any copy, and no pointer to one is stored in game.dll, so the code that picks a tip reaches its list through a runtime object. 32 of the 82 are jokes or lore ("Don't die!", the seven ministries; `research/tips.py` JOKES); the others are real advice.

`research/tips.py` lists the ids and copies from the dump. The text lookup takes the first table holding an id (HD2Runtime's table comes after the game's), so a tip can't be overridden under its own id: a list slot has to point at another id.

## Signatures

`research/signatures.py` generates them from a game.dll dump and writes them, with the shared signature engine, into `true_intel.lua`. At startup each is tried at the known build's address, else game.dll is searched; a signature must match exactly once, and a value read from several places must agree. Values are read from the matched code (rip-relative operands, displacements).

| Signature | RVA | Fields | Use |
| --- | --- | --- | --- |
| `passive_value` | 0x11DA090 | manager global, index table +0x30, record array +0x20, rows +0x10 (stride 0x10), row count +0x18 | required: every line |
| `stat_applier` | 0x11DA465 | stat rows +0x20, stat row count +0x28 | required: the stat lines |
| `armor_scale` | 0x19161D0 | armor scale float global, the call to PassiveValue | optional: without it the armor lines stay the game's |
| `operation_missions` | 0x12BF9FA | board global, record mission count +0x58, row indices +0x55, states +0x48, mission rows +0xF9A10, their count +0x61F8 from them, row size 0x4C, row type +0x40 | optional: operation research |
| `selected_operation` | 0x6FDE4A | selected index +0x17A2A0, record count 0x6E, record size 0x5C, records +0xF7280, active +0x34 | optional: operation research |
| `mission_definitions` | 0xFD2A24 | definitions table, entry size 0x380, count 0xA2 | optional: operation research |
| `presenters` | 0x662520 | UI global, presenter manager +0x4288, depth +0x28, stack +0x14 | optional: operation research |
| `ui_manager` | 0xB938D4 | UI manager global | optional: the operation card |
| `label_init` | 0x143AFA0 | label type 7, text id +0x110, argument count +0x268 (and the label's other fields) | optional: the operation card |
| `label_text_call` | 0x190A7A2 | `set_label`, the COUNT key 0xAB2A7B35, `set_string_arg` | optional: the operation card |

Without the required two the mod stays off; each optional one turns off only what needs it.

## Credits and prior art

- [Bingus Shared Loader](https://github.com/CowboyBingus/BingusSharedLoader) by CowboyBingus; its `bingus_text.lua` resolves the translations.
- Uses code / research from HD2Runtime by SkyeShade, https://github.com/SkyeShade/HD2Runtime: its text table holds the lines, its armor passive research agrees on GUNSLINGER's x1.6 ("Gunslinger's actual reload multiplier is 1.6 in this build"), and its catalogues (armor passives, kits, status effects, missions) were checked against; its research (boosters, Helldiver fields, armor, enemies, stratagems, status effects) gives the loading tips' numbers. No code of HD2Runtime is used or bundled.
- Know Your Constellation (CowboyBingus, Vanilla Plus Megapack) located the galactic map's presenter stack, the mission board, the selected operation, the operation records, the map's mission descriptor and its operation frame.
- The text widget technique (the `#COUNT` template with a string argument) is Mod Options Menu's (CowboyBingus); the label signatures come from Flexible Loadouts and One Click Armor Set, by True Intel's author.
- Helmet Passives Reborn (the passive pipeline, the Armory panel, the text module's use) and [Impatient Diver](https://github.com/Alomare/ImpatientDiver) (the presenter manager) are by the same author.
- Passive records from [FileDiver](https://github.com/xypwn/filediver); armor ratings checked against the [Helldivers 2 wiki](https://helldivers.wiki.gg).

## Research tools

- `research/lines.py [--check]`: the passive records and `locales/` -> every line, the panel's room in every language, [research/lines.md](research/lines.md) and the script's LINES block.
- `research/signatures.py [--check]`: the signatures and the signature engine in the script.
- `tests/test_release.py`: runs the built entry under LuaJIT against a game.dll dump (not included), with the game's real passive records and HD2Runtime's text table simulated.
