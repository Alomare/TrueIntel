"""True Intel' code signatures: checked against the game.dll dump and written into true_intel.lua between the
SIGNATURES markers, with the shared signature engine (tools/sigscan.lua) between the SIGNATURE ENGINE markers.

Globals and offsets are read from the matched code (rip-relative operands, displacements). Sources: Helmet Passives
Reborn's NOTES.md (the passive pipeline) and this mod's NOTES.md ("The real numbers").

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
