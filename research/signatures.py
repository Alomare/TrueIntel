"""True Intel' code signatures: checked against the game.dll dump and written into true_intel.lua between the
SIGNATURES markers, with the shared signature engine (tools/sigscan.lua) between the SIGNATURE ENGINE markers.

Globals and offsets are read from the matched code (rip-relative operands, displacements). Sources: this mod's
RESEARCH.md ("The passive tables", "What the values really do", "Signatures").

Usage (from the workspace root): python -B mods/TrueIntel/research/signatures.py [--check]
  --check   only verify: every signature matches once and the script's blocks are current (exit 1 otherwise)
"""
import sys
from pathlib import Path

MOD = Path(__file__).resolve().parents[1]
ROOT = MOD.parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sigspec  # noqa: E402

SCRIPT = MOD / 'true_intel.lua'

SPECS = [
    # PassiveValue(passive id, key) (0x11DA090), the whole function: the customization manager global, its passive id
    # -> record index table (an inline u32 array, -1 = no record), its passive record pointer array, and a record's
    # modifier rows {pointer, count}. The rows' 16-byte stride is the same 0x10 as the rows pointer (`add rcx, 0x10`):
    # both are read and must agree. Required: every line needs it.
    {'name': 'passive_value', 'start': 0x11da090, 'end': 0x11da10b,
     'fields': {'customization': (0x33264f8, 'rip'), 'passive_index': (0x30, 'u8'), 'passives': (0x20, 'u8'),
                'rows': (0x10, 'u8'), 'row_count': (0x18, 'u8')}},
    # The spawn stat applier (0x11DA190) on the armor kit's passive (0x11DA465): kit +0x1C -> index table +0x30 -> the
    # record, then its stat rows {+0x20 pointer, +0x28 count} (12 bytes each: {stat, add, mul}; stat 20 = Count is
    # skipped). The passive array is +0x20 too: both occurrences must agree. Required: the stat lines need it.
    {'name': 'stat_applier', 'start': 0x11da465, 'end': 0x11da4cb,
     'fields': {'stat_rows': (0x20, 'u8'), 'stat_row_count': (0x28, 'u8')}},
    # The Armory's armor stats (0x1915EB0): for stat 0 the armor rating is 100 + (PassiveValue(kit passive, kit armor,
    # AFAE3B47, literal) - 1) x 50, so a passive's armor-rating row shows as its value x 50. The scale is a float
    # global (rip operand of the first movss, 50.0 in this build). Optional: without it the armor lines stay vanilla.
    {'name': 'armor_scale', 'start': 0x19161d0, 'end': 0x1916231, 'optional': True,
     'fields': {'armor_scale': (0x23c76fc, 'rip'), 'call_passive_value': (0x11da090, 'call')}},
    # Operation intel (2-recon-1, read-only probe; RESEARCH.md "Operations and missions"). All optional: without them the probe
    # stays off and the armor lines are unaffected.
    # The Operation/Create request (0x12BF770), its missions loop: the mission board global, an operation record's
    # mission count (u8) and its mission row indices (u8 each), the board's mission rows (table offset, count relative to
    # the table, 76-byte rows), a row's type (the request's "type") and the record's per-mission states (u32 each).
    {'name': 'operation_missions', 'start': 0x12bf9fa, 'end': 0x12bfadf, 'optional': True,
     'fields': {'board': (0x347cee8, 'rip'), 'op_mission_count': (0x58, 'u8'), 'op_mission_rows': (0x55, 'u8'),
                'mission_rows': (0xf9a10, 'u32'), 'mission_row_count': (0x61f8, 'u32'), 'mission_row': (0x4c, 'u8'),
                'mission_type': (0x40, 'u8'), 'op_mission_states': (0x48, 'u8')}},
    # The map's selected-operation getter (0x6FDE4A): board + 0x17A2A0 = the selected operation's index (-1 = none),
    # fewer than 0x6E records of 0x5C bytes at board + 0xF7280, + 0x34 = active.
    {'name': 'selected_operation', 'start': 0x6fde4a, 'end': 0x6fde6e, 'optional': True,
     'fields': {'op_selected': (0x17a2a0, 'u32'), 'op_max': (0x6e, 'u8'), 'op_record': (0x5c, 'u8'),
                'operations': (0xf7280, 'u32'), 'op_active': (0x34, 'u8')}},
    # A loop over every mission definition (0xFD2A24): the static table (0x380-byte records filled at start-up, + 0 = the
    # mission id HD2Runtime keys its catalogue by) and its count, 0xA2 = 162.
    {'name': 'mission_definitions', 'start': 0xfd2a24, 'end': 0xfd2a46, 'optional': True,
     'fields': {'definitions': (0x3773420, 'rip'), 'definition_size': (0x380, 'u32'), 'definition_count': (0xa2, 'u32')}},
    # Impatient Diver's "is the briefing presenter open?" (0x662520): the UI state global, its presenter manager, the
    # presenter stack and its depth. The top presenter 15 is the galactic map (Know Your Constellation).
    {'name': 'presenters', 'start': 0x662520, 'end': 0x662557, 'optional': True,
     'fields': {'ui': (0x347ce28, 'rip'), 'presenters': (0x4288, 'u32'), 'depth': (0x28, 'u8'), 'stack': (0x14, 'u8')}},
    # The game's text widgets (2-recon-2: the operation card's missions; RESEARCH.md "Text widgets"). All optional:
    # without them the card shows the game's text alone.
    # The UI manager global (One Click Armor Set's): its screens {pointer, type} and the galactic map's registry.
    {'name': 'ui_manager', 'start': 0xb938d4, 'end': 0xb938e0, 'optional': True,
     'fields': {'ui_manager': (0x3326e68, 'rip')}},
    # A label's initializer (0x143AFA0, Flexible Loadouts'): the widget type 7, its text id +0x110 and its argument
    # count +0x268 (u8; up to 14 arguments {key, type, value} of 24 bytes from +0x118).
    {'name': 'label_init', 'start': 0x143afa0, 'end': 0x143b025, 'optional': True,
     'fields': {'label_type': (7, 'u32'), 'label_text_id': (0x110, 'u32'), 'label_arg_count': (0x268, 'u32'),
                'label_cache': (0x270, 'u32'), 'label_handle': (0x278, 'u32'), 'label_font_size': (0x27c, 'u32'),
                'label_font_material': (0x2a8, 'u32'), 'label_last': (0x2b4, 'u32')}},
    # A game label getting its text from a template and one string argument (0x190A7A2, Flexible Loadouts'):
    # set_label(w, id), then set_string_arg(w, key, char *) with the COUNT key 0xAB2A7B35.
    {'name': 'label_text_call', 'start': 0x190a7a2, 'end': 0x190a7c3, 'optional': True,
     'fields': {'text_set_label': (0x143bf90, 'call'), 'text_count_key': (0xab2a7b35, 'u32'),
                'call_set_string_arg': (0x143c950, 'call')}},
]


def main():
    rows = sigspec.build(SPECS)
    sigspec.report(rows)
    if '--check' in sys.argv:
        problems = sigspec.check(SCRIPT, rows)
        for p in problems:
            print('STALE:', p)
        sys.exit(1 if problems else 0)
    sigspec.write(SCRIPT, rows)
    print('written to', SCRIPT.name)


if __name__ == '__main__':
    main()
