"""Offline test of True Intel under LuaJIT, with the real game.dll code as fake process memory.

The Ghidra-ready dump (_research/game_25480438.dll, offsets == RVAs; not included) is mapped at a fake base, so the
signatures and the values read from the matched code are the game's own (the Armory's armor scale is the dump's 50.0);
WriteProcessMemory writes over the dump or into the fake heap. The customization manager holds the game's real passive
records (decoded from FileDiver's mirror by research/lines.py) on the fake heap, in the layout PassiveValue
(0x11DA090) and the stat applier (0x11DA190) read. HD2Runtime's text module is faked; Mod Options Menu and Mod
Bindings Menu are present, to show the mod registers nothing with them. The script runs as the build assembles it
(tools/entry.py: the text kit ahead of it).

Run from the workspace root:  python -B mods/TrueIntel/tests/test_release.py
"""
import struct
import sys
import tempfile
from pathlib import Path

from lupa.luajit21 import LuaRuntime

MOD = Path(__file__).resolve().parent.parent
ROOT = MOD.parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(MOD / 'research'))
from entry import entry_text  # noqa: E402
import lines as research  # noqa: E402
import signatures  # noqa: E402
import sigspec  # noqa: E402

SOURCE = entry_text(MOD, 'true_intel.lua')
DUMP = (ROOT / '_research' / 'game_25480438.dll').read_bytes()
STRINGS = research.load_strings()
LOCALES = research.load_locales()
PASSIVES = research.decode_passives(STRINGS['us'])

BASE = 0x40000000
MANAGER, ARRAY, RECORDS, ROWS, STATS = 0x20000000, 0x21000000, 0x22000000, 0x23000000, 0x24000000
CUSTOMIZATION = 0x33264F8
TYPES = {'Set': 0, 'Add': 1, 'Multiply': 2, 'Time': 3}
CODES = ['us', 'gb', 'bp', 'de', 'es', 'fr', 'it', 'jp', 'ko', 'ms', 'pl', 'pt', 'ru', 'cn', 'tc']

HARNESS = r'''
local logdir, image = ...
local real_ffi = require('ffi')
local ffi = real_ffi
local BASE = 0x40000000
fake = {writes = 0, write_log = {}, refuse_writes = false}
CowboyBingusModLoader = {api = 1, open_log = function(name)
    if type(name) ~= 'string' or not name:match('^[%w_-]+%.log$') then return nil end
    return io.open(logdir .. '/' .. name, 'w')
end}
local patches, heap = {}, {}
local function read_mem(a, n)
    if a >= BASE and a + n <= BASE + #image then
        local s = image:sub(a - BASE + 1, a - BASE + n)
        for _, p in ipairs(patches) do
            local lo, hi = math.max(a, p[1]), math.min(a + n, p[1] + #p[2])
            if lo < hi then s = s:sub(1, lo - a) .. p[2]:sub(lo - p[1] + 1, hi - p[1]) .. s:sub(hi - a + 1) end
        end
        return s
    end
    for k, v in pairs(heap) do
        if k <= a and a + n <= k + #v then return v:sub(a - k + 1, a - k + n) end
    end
end
fake.patch = function(rva, bytes) patches[#patches + 1] = {BASE + rva, bytes} end
fake.heap = function(a, bytes) heap[a] = bytes end
local function poke(a, bytes)
    for k, v in pairs(heap) do
        if k <= a and a + #bytes <= k + #v then heap[k] = v:sub(1, a - k) .. bytes .. v:sub(a - k + #bytes + 1); return true end
    end
end
fake.poke = poke
-- Reads for the Python side (lupa decodes Lua strings as UTF-8): a u32, or bytes as hex.
fake.peek32 = function(a)
    local s = read_mem(a, 4)
    local b1, b2, b3, b4 = s:byte(1, 4)
    return b1 + 256 * b2 + 65536 * b3 + 16777216 * b4
end
fake.peek = function(a, n)
    return (read_mem(a, n):gsub('.', function(c) return string.format('%02x', c:byte()) end))
end
-- kernel32's stand-ins, by export name.
local k32 = {
    GetCurrentProcess = function() return nil end,
    GetModuleHandleA = function(name) return ffi.cast('void *', BASE) end,
    ReadProcessMemory = function(p, addr, buf, size, got)
        local s = read_mem(tonumber(ffi.cast('uint64_t', addr)), tonumber(size))
        if not s then return 0 end
        ffi.copy(buf, s, #s); got[0] = #s; return 1
    end,
    WriteProcessMemory = function(p, addr, buffer, size, got)
        local a = tonumber(ffi.cast('uint64_t', addr))
        local bytes = ffi.string(buffer, tonumber(size))
        if fake.refuse_writes then return 0 end
        if a >= BASE and a + #bytes <= BASE + #image then
            patches[#patches + 1] = {a, bytes}
        elseif not poke(a, bytes) then
            return 0
        end
        fake.writes = fake.writes + 1
        fake.write_log[#fake.write_log + 1] = a
        got[0] = #bytes; return 1
    end,
}
-- kernel32 as FFI sees it (One Click Armor Set's harness): a call goes through the C declaration of the name it is
-- made by (every addon shares one FFI namespace, which keeps a name's first declaration; a later ffi.cdef of it
-- fails), so its arguments are converted, or refused, as in the game; the stand-in is called back through that
-- declaration (JIT off: a callback can't run under a compiled C call).
require('jit').off()
local declared, callbacks = {}, {}
local function cdef(text)
    real_ffi.cdef(text)
    local ret, name, params, rest = text:match('^%s*([^;(]-)%s*([%w_]+)%s*(%b())%s*([^;]*);%s*$')
    if name and not declared[name] then
        declared[name] = {type = ret .. '(*)' .. params, symbol = rest:match('__asm__%("([%w_]+)"%)') or name}
    end
end
local kernel32 = setmetatable({}, {__index = function(_, name)
    local d = assert(declared[name], 'missing declaration for symbol ' .. name)
    callbacks[name] = callbacks[name] or real_ffi.cast(d.type, assert(k32[d.symbol], 'no stand-in for ' .. d.symbol))
    return callbacks[name]
end})
package.loaded.ffi = setmetatable({load = function() return kernel32 end, cdef = cdef}, {__index = real_ffi})
-- Another mod loaded first declared kernel32's functions under their own names, with other types (One Click Armor
-- Set V3's case: a player's log, 2026-10-10).
for _, decl in ipairs({'uintptr_t GetCurrentProcess(void);', 'uintptr_t GetModuleHandleA(const char *name);',
                       'int ReadProcessMemory(uintptr_t process, uintptr_t address, uintptr_t buffer, size_t size, '
                           .. 'size_t *read);',
                       'int WriteProcessMemory(uintptr_t process, uintptr_t address, const char *buffer, size_t size, '
                           .. 'size_t *written);'}) do
    cdef(decl)
end
fake.declared = declared

-- The menus: present, and nothing may register with them.
fake.specs, fake.bound = {}, {}
ModOptionsMenu = {api = 1, register_option = function(id, spec) fake.specs[#fake.specs + 1] = id; return true end,
                  get = function() end, set = function() end, on_change = function() end}
ModBindingsMenu = {api = 1, register_binding = function(id) fake.bound[#fake.bound + 1] = id; return true end,
                   is_down = function() return false end}

-- HD2Runtime: the main module, its development text module (handles: text id = 0xC0000000 + order, the value checked
-- as HD2Runtime checks it: a table {default = text, <game language> = text}; ensure registers the one table,
-- fake.texts.refuse = {code, reason} refuses; resolves: NOT_REGISTERED once fake.texts.registered is false, a language
-- change) and the write adapter.
local hd2 = {version = '0.40.0'}
package.preload['mods/skyeshade/hd2runtime'] = function() if fake.no_runtime then error('module not found') end
    return hd2 end
local CODES = {}
for code in ('us gb bp de es fr it jp ko ms pl pt ru cn tc'):gmatch('%a+') do CODES[code] = true end
fake.texts = {order = {}, by_id = {}, ensures = 0, registered = false, refuse = nil}
package.preload['hd2runtime/runtime/text_resources'] = function()
    local t = {}
    function t.handle(id, value, owner)
        assert(owner == 'mods/alomare/true_intel', 'a text of another owner')
        assert(type(id) == 'string' and #id <= 64 and id:match('^[a-z0-9_]+$'), 'bad text id ' .. tostring(id))
        assert(type(value) == 'table' and getmetatable(value) == nil and value.default, 'text must be a table')
        for k, v in pairs(value) do
            assert(k == 'default' or CODES[k], 'unsupported text language ' .. tostring(k))
            assert(type(v) == 'string' and #v >= 1 and #v <= 512 and not v:find('[%z\1-\31]'), 'bad text ' .. tostring(v))
            assert(not v:find('{number}', 1, true), 'a placeholder left in ' .. v)
        end
        assert(not fake.texts.by_id[id], 'text defined twice: ' .. id)
        local h = {id = id, values = value, loc = 0xC0000000 + #fake.texts.order + 1}
        fake.texts.order[#fake.texts.order + 1] = h
        fake.texts.by_id[id] = h
        return h
    end
    function t.id_bytes(h)
        local v = h.loc
        return string.char(v % 256, math.floor(v / 256) % 256, math.floor(v / 65536) % 256, math.floor(v / 16777216) % 256)
    end
    function t.ensure(adapter)
        assert(type(adapter) == 'table' and adapter.write_capable, 'ensure without the write adapter')
        fake.texts.ensures = fake.texts.ensures + 1
        if fake.texts.refuse then return nil, fake.texts.refuse[1], fake.texts.refuse[2] end
        local action = fake.texts.registered and 'present' or 'appended'
        fake.texts.registered = true
        return true, {action = action, index = 18, count = 18, language = 'us'}
    end
    function t.resolves(adapter, h)
        if fake.texts.registered then return true end
        return nil, 'NOT_REGISTERED', 'not in any registered table'
    end
    return t
end
package.preload['hd2runtime/runtime/windows_write'] = function()
    return {create = function() return {write_capable = true} end}
end
function step(n)
    for i = 1, n or 1 do update(0.016) end
end
'''


def records(extra_hpr=False, edit=None):
    """The game's passive records as {id: (rows, stats)}: rows [[key, type, value, text]], stats [[stat, add, mul]],
    after `edit` (a function on that dict); with Helmet Passives Reborn's seven records (ids 23-29, text-only rows)."""
    out = {}
    for pid, p in PASSIVES.items():
        out[pid] = ([[r['key'], TYPES[r['type']], r['value'], r['text_id']] for r in p['rows']],
                    [[s, v['add'], v['mul']] for s, v in sorted(p['stats'].items())])
    if extra_hpr:
        for pid in range(23, 30):
            out[pid] = ([[0, 0, 0.0, 0xD0000000 + pid], [0, 0, 0.0, 0xD0000100 + pid]], [])
    if edit:
        edit(out)
    return out


def manager(lua, recs):
    """The customization manager on the fake heap: the passive array (the game's order: ids ascending), the index
    table (42 ids), each record (56 bytes) with its modifier rows and stat rows. Returns {id: (record, rows, stats)}."""
    f = lua.globals().fake
    f.patch(CUSTOMIZATION, struct.pack('<Q', MANAGER))
    ids = sorted(recs)
    head = bytearray(0x30 + 42 * 4)
    struct.pack_into('<QI', head, 0, 0x2F000000, 411)
    struct.pack_into('<QI', head, 0x20, ARRAY, len(ids))
    for i in range(42):
        struct.pack_into('<I', head, 0x30 + i * 4, ids.index(i) if i in ids else 0xFFFFFFFF)
    f.heap(MANAGER, bytes(head) + b'\0' * 0x40)
    f.heap(ARRAY, b''.join(struct.pack('<Q', RECORDS + k * 0x100) for k in range(len(ids))))
    at = {}
    for k, pid in enumerate(ids):
        rows, stats = recs[pid]
        rows_at, stats_at = ROWS + k * 0x100, STATS + k * 0x100
        rec = struct.pack('<IIQQIIQIII', pid, 0xA0000000 + pid, 0x1000 + pid, rows_at, len(rows), 0,
                          stats_at if stats else 0, len(stats), 0, 0)
        f.heap(RECORDS + k * 0x100, rec + b'\0' * (0x100 - len(rec)))
        f.heap(rows_at, b''.join(struct.pack('<IIfI', *r) for r in rows) + b'\0' * 0x10)
        f.heap(stats_at, b''.join(struct.pack('<Iff', *s) for s in stats) + b'\0' * 0x10)
        at[pid] = (RECORDS + k * 0x100, rows_at, stats_at)
    return at


def row_at(at, recs, pid, key):
    """The address of passive pid's row with key."""
    for i, r in enumerate(recs[pid][0]):
        if r[0] == key:
            return at[pid][1] + 16 * i
    raise KeyError((pid, key))


def u32_at(lua, a):
    return lua.globals().fake.peek32(a)


def rows_snapshot(lua, at, recs):
    """Every record's modifier rows (text ids masked) and stat rows, as bytes."""
    f, out = lua.globals().fake, []
    for pid, (_, rows_at, stats_at) in sorted(at.items()):
        rows, stats = recs[pid]
        blob = bytearray(bytes.fromhex(f.peek(rows_at, 16 * len(rows)))) if rows else bytearray()
        for i in range(len(rows)):
            blob[16 * i + 12:16 * i + 16] = b'\0\0\0\0'
        out.append(bytes(blob))
        if stats:
            out.append(bytes.fromhex(f.peek(stats_at, 12 * len(stats))))
    return out


def new_run():
    lua = LuaRuntime(unpack_returned_tuples=True)
    logdir = Path(tempfile.mkdtemp(prefix='ts_test_'))
    lua.execute(HARNESS, str(logdir), DUMP)
    return lua, logdir


def started(recs=None, before=None, frames=5):
    """A run with the manager in place, the script loaded and `frames` frames played."""
    lua, logdir = new_run()
    recs = recs or records()
    at = manager(lua, recs)
    if before:
        before(lua, at, recs)
    lua.execute(SOURCE)
    lua.execute('step(%d)' % frames)
    log = lambda: (logdir / 'TrueIntel.log').read_text(encoding='utf-8')
    status = lambda: (logdir / 'TrueIntel_STATUS.log').read_text(encoding='utf-8')
    return lua, at, recs, log, status


def texts_by_id(lua):
    """Our defined texts: id -> {loc, values (language -> text)}."""
    out = {}
    for h in lua.globals().fake.texts.order.values():
        out[h.id] = {'loc': h.loc, 'values': dict(h['values'].items())}
    return out


GUN, PADDING, OXY, BLUNT, ADREN, REINF, PEAK, GRIT = 18, 1, 38, 40, 34, 35, 12, 41
RELOAD, ARMOR, JOG, SPRINT, KNOCK, STAMINA, ERGO = 0xB4F88129, 0xAFAE3B47, 0xCD79A687, 0xF6D67313, 0x11A3C04C, \
    0xA189ADB6, 0xC8CCB6FA
NBSP = ' '


def run():
    ok = []

    def check(cond, what):
        ok.append(bool(cond))
        print('PASS' if cond else 'FAIL', what)

    check(not sigspec.check(signatures.SCRIPT, sigspec.build(signatures.SPECS)),
          "the script's signature blocks match research/signatures.py")
    chosen = research.targets(PASSIVES, LOCALES['en'])
    problems, _ = research.budget(PASSIVES, chosen, STRINGS, LOCALES)
    check(SOURCE.count(research.lua_block(chosen)) == 1 and not problems,
          "the script's LINES block matches research/lines.py; every passive fits the panel in all 15 languages")
    shown = [t for t in chosen if t[2]['shown']]
    check(len(chosen) == 19 and len(shown) == 12, 'research: 19 lines, 12 shown today (%d, %d)' % (len(chosen),
                                                                                                    len(shown)))
    check(set(LOCALES) == {'en', 'en-GB', 'de', 'es', 'es-419', 'fr', 'it', 'ja', 'ko', 'pl', 'pt', 'pt-BR', 'ru',
                           'zh-Hans', 'zh-Hant'}
          and all(set(LOCALES[t]) == set(LOCALES['en']) for t in LOCALES if t not in ('en', 'en-GB')),
          'locales: every text in 13 languages, British English for "armour"')
    for name in ('ModOptionsMenu', 'ModBindingsMenu', 'register_option', 'register_binding', 'Keyboard', 'listed_numbers',
                 'not {listed}'):
        check(name not in SOURCE.split('-- END SIGNATURE ENGINE', 1)[1], 'the release has no ' + name)

    # Without HD2Runtime: not available, nothing written.
    lua0, logdir0 = new_run()
    lua0.execute('fake.no_runtime = true')
    lua0.execute(SOURCE)
    lua0.execute('step(3)')
    status0 = (logdir0 / 'TrueIntel_STATUS.log').read_text()
    check(status0.startswith('NOT AVAILABLE - HD2Runtime is not installed or did not load')
          and lua0.globals().fake.writes == 0, 'no HD2Runtime: refused, nothing written (%r)' % status0.splitlines()[0])

    # The game's records: twelve lines made, texts registered, rows swapped.
    lua, at, recs, log, status = started()
    f = lua.globals().fake
    V = lua.eval('TrueIntel._test.signature_values()')
    check(V.customization == CUSTOMIZATION and V.passive_index == 0x30 and V.passives == 0x20 and V.rows == 0x10
          and V.row_count == 0x18 and V.stat_rows == 0x20 and V.stat_row_count == 0x28 and V.armor_scale == 0x23C76FC,
          'signatures: every value read from the game\'s code')
    lines = lua.eval('TrueIntel._test.lines')
    check(lines.state == 'applied' and len(lines.list) == 12, 'twelve lines applied (%s, %d)' % (lines.state,
                                                                                               len(lines.list)))
    tx = texts_by_id(lua)
    check(len(tx) == 12 and f.texts.ensures == 1 and 'p18_b4f88129_60' in tx,
          'twelve texts in one registration (%d, %d ensures)' % (len(tx), f.texts.ensures))
    check(all(set(t['values']) == set(CODES) | {'default'} and t['values']['default'] == t['values']['us']
              for t in tx.values()), 'every text in all 15 game languages, English the default')
    gun = tx['p18_b4f88129_60']['values']
    check(gun['us'] == 'Increases sidearms reload speed by <c=#COLOR>60%</c>.'
          and gun['de'] == 'Erhöht die Nachladegeschwindigkeit von Seitenwaffen um <c=#COLOR>60 %</c>.'
          and gun['fr'].endswith('<c=#COLOR>60' + NBSP + '%</c>.') and gun['jp'] == 'ハンドガンのリロード速度が<c=#COLOR>60％</c>上昇する。'
          and gun['ms'].endswith('<c=#COLOR>60' + NBSP + '%</c>.') and gun['bp'].endswith('<c=#COLOR>60%</c>.'),
          'GUNSLINGER: 60% from stat 15, in each language\'s number format')
    pad = tx.get('p1_afae3b47_50', {}).get('values', {})
    check(pad.get('us') == 'Provides <c=#COLOR>+50</c> armor rating.'
          and pad.get('gb') == 'Provides <c=#COLOR>+50</c> armour rating.'
          and pad.get('de') == 'Bietet <c=#COLOR>+50</c> Panzerungswertung.'
          and 'p35_afae3b47_30' in tx and 'p14_afae3b47_25' in tx and 'p34_afae3b47_25' in tx and 'p40_afae3b47_25' in tx,
          'armor rating: +50 (EXTRA PADDING), +30, +25, from the dump\'s 50.0; "armour" in British English')
    stamina = tx.get('p34_a189adb6', {}).get('values', {})
    check(stamina.get('us') == 'When the wearer takes damage, they regain <c=#COLOR>#BONUS%</c> stamina per '
                               '<c=#COLOR>1%</c> of health lost.'
          and all(t['values'][c].count('#BONUS') == 1 for k, t in tx.items() for c in CODES
                  if k in ('p12_c8ccb6fa', 'p34_a189adb6', 'p33_11a3c04c', 'p38_cd79a687')),
          'the bonus lines keep the game\'s #BONUS in every language; both stamina numbers coloured')
    check(u32_at(lua, row_at(at, recs, GUN, RELOAD) + 12) == tx['p18_b4f88129_60']['loc']
          and u32_at(lua, row_at(at, recs, PADDING, ARMOR) + 12) == tx['p1_afae3b47_50']['loc']
          and u32_at(lua, row_at(at, recs, OXY, JOG) + 12) == tx['p38_cd79a687']['loc'],
          'rows: GUNSLINGER, EXTRA PADDING and OXYGENATOR hold our text ids')
    gun_draw = row_at(at, recs, GUN, 0xAD5289FE)
    check(u32_at(lua, gun_draw + 12) == 0x04CD8147 and u32_at(lua, row_at(at, recs, OXY, SPRINT) + 12) == 0,
          'rows: a matching copy (GUNSLINGER\'s draw) and a textless row (OXYGENATOR\'s sprint) untouched')
    made_rows = {row_at(at, recs, L.spec.passive, L.spec.row) + 12 for L in lines.list.values()}
    check(set(f.write_log.values()) == made_rows and f.writes == 12,
          'only the twelve rows\' text ids were written (%d writes)' % f.writes)
    base_snapshot = rows_snapshot(lua, at, recs)
    clean_lua, clean_at, _, _, _ = started(frames=0)
    check(rows_snapshot(clean_lua, clean_at, recs) == base_snapshot,
          'no gameplay change: every key, type, value and stat row is the game\'s')
    check(len(list(f.specs.values())) == 0 and len(list(f.bound.values())) == 0,
          'nothing registered with Mod Options Menu or Mod Bindings Menu')
    check(all(f.declared['ti_' + n].symbol == n for n in ('GetCurrentProcess', 'GetModuleHandleA', 'ReadProcessMemory',
                                                         'WriteProcessMemory'))
          and f.declared.ReadProcessMemory.type.startswith('int(*)(uintptr_t'),
          'kernel32 under the mod\'s own names, working past another mod\'s declarations of the bare names')
    lg = log()
    check('exact: 50% (stat 16 x1.5)' in lg and 'Lines: 12 made, 7 exact already, 0 skipped' in lg
          and 'armor rating scale 50' in lg and 'Lines applied: 12 of 12 rows' in lg,
          'log: 12 made, the 7 matching copies exact, the armor scale')
    check('Text: language de: 11 of 11 texts translated' in lg and 'Text: language en-GB: 1 of 11' in lg,
          'log: every language\'s translation count')
    check(status().startswith('WORKING\nTrue Intel V1'), 'status: WORKING, V1')

    # A language change: the game drops our table; two misses, registered again; the rows stay ours.
    f.texts.registered = False
    lua.execute('step(40)')
    check(f.texts.registered and f.texts.ensures == 2 and '; registered again' in log()
          and u32_at(lua, row_at(at, recs, GUN, RELOAD) + 12) == tx['p18_b4f88129_60']['loc'],
          'language change: registered again, the rows stay ours')
    # ... while the game is still switching: the game's ids back until the table is in again.
    lua.execute('fake.texts.registered = false; fake.texts.refuse = {"UNAVAILABLE", "switching"}; step(40)')
    check(lines.state == 'text lost' and u32_at(lua, row_at(at, recs, GUN, RELOAD) + 12) == 0xCE97302E,
          'texts unavailable: the game\'s ids back (no blank line)')
    lua.execute('fake.texts.refuse = nil; step(40)')
    check(lines.state == 'applied' and u32_at(lua, row_at(at, recs, GUN, RELOAD) + 12) == tx['p18_b4f88129_60']['loc'],
          'texts back: ours again')
    # A row the game reset: written again at the next check.
    gun_row = row_at(at, recs, GUN, RELOAD)
    f.poke(gun_row + 12, struct.pack('<I', 0xCE97302E))
    lua.execute('step(640)')
    check(u32_at(lua, gun_row + 12) == tx['p18_b4f88129_60']['loc'], 'a reset row is written again at the next check')
    # Another mod writes a row after ours: left alone at the next check, logged.
    pad_row = row_at(at, recs, PADDING, ARMOR)
    f.poke(pad_row + 12, struct.pack('<I', 0x55555555))
    lua.execute('step(640)')
    check(u32_at(lua, pad_row + 12) == 0x55555555 and "the row holds 55555555, not ours nor the game's" in log(),
          'a row another mod took later: left alone')
    f.poke(pad_row + 12, struct.pack('<I', tx['p1_afae3b47_50']['loc']))
    # A live change (HD2Runtime's perk editor): logged once, the line keeps its number.
    f.poke(at[GUN][2] + 8, struct.pack('<f', 1.7))  # stat 15 is GUNSLINGER's first stat row: its mul
    lua.execute('step(1300)')
    check(log().count('the live value changed') == 1, 'a live value change is logged once')
    check(lua.eval('TrueIntel.errors') == 0, 'no errors')

    # A translation pack (bingus_text's shared registry) overrides the bundled text for its language.
    lua1, _, _, _, _ = started(before=lambda l, a, r: l.execute(
        "BingusTranslations = {version = 1, serial = 1, packs = {{language = 'ko', name = 'test', mods = "
        "{true_intel = {['line.armor'] = '<c=#COLOR>+{number}</c> TEST'}}}}}"))
    tx1 = texts_by_id(lua1)
    check(tx1['p1_afae3b47_50']['values']['ko'] == '<c=#COLOR>+50</c> TEST'
          and tx1['p1_afae3b47_50']['values']['jp'] == 'アーマー評価が<c=#COLOR>+50</c>上昇する。',
          'a translation pack overrides its language only')

    # Another mod's text on GUNSLINGER's reload row: that line is left alone.
    def foreign(lua_, at_, recs_):
        lua_.globals().fake.poke(row_at(at_, recs_, GUN, RELOAD) + 12, struct.pack('<I', 0x12345678))
    lua2, at2, recs2, log2, _ = started(before=foreign)
    check(len(lua2.eval('TrueIntel._test.lines').list) == 11 and u32_at(lua2, row_at(at2, recs2, GUN, RELOAD) + 12)
          == 0x12345678 and "text id 12345678 (another mod's?)" in log2(), 'another mod\'s text id: left alone')

    # GUNSLINGER fixed by the game (stat 15 x1.4): its line is exact, none made.
    def fixed(recs_):
        recs_[GUN][1][0][2] = 1.4
    lua3, _, _, log3, _ = started(records(edit=fixed))
    check(len(lua3.eval('TrueIntel._test.lines').list) == 11 and 'exact: 40% (stat 15 x1.4)' in log3(),
          'GUNSLINGER fixed by the game: no line')

    # A watched copy that starts to differ (REINFORCED EPAULETTES' stat 13 x1.35): its line appears, in every language.
    def epaulettes(recs_):
        recs_[10][1][0][2] = 1.35
    lua3a, _, _, _, _ = started(records(edit=epaulettes))
    tx3a = texts_by_id(lua3a)
    check(len(lua3a.eval('TrueIntel._test.lines').list) == 13
          and tx3a.get('p10_cc530b21_35', {}).get('values', {}).get('ru')
          == 'Повышает скорость перезарядки основного оружия на <c=#COLOR>35%</c>.',
          'a watched copy that differs gets its line (35%)')

    # A stat row with an add (not a plain multiplier): no percent line.
    def added(recs_):
        recs_[GUN][1][0][1] = 0.1
    lua3b, _, _, log3b, _ = started(records(edit=added))
    check(len(lua3b.eval('TrueIntel._test.lines').list) == 11 and 'stat 15 adds 0.1' in log3b(),
          'a stat row with an add: no line')

    # OXYGENATOR's jog and sprint differ: no line (it would name one speed for both).
    def apart(recs_):
        for r in recs_[OXY][0]:
            if r[0] == SPRINT:
                r[2] = 1.2
    lua4, _, _, log4, _ = started(records(edit=apart))
    check(len(lua4.eval('TrueIntel._test.lines').list) == 11 and 'row F6D67313 differs from CD79A687' in log4(),
          'OXYGENATOR\'s speeds differ: no line')

    # Helmet Passives Reborn's seven records (39 in all): the same twelve lines.
    lua5, _, _, _, _ = started(records(extra_hpr=True))
    check(len(lua5.eval('TrueIntel._test.lines').list) == 12 and lua5.eval('TrueIntel._test.lines').state == 'applied',
          'with Helmet Passives Reborn\'s 39 records: the same twelve lines')

    # The text registry full: nothing written, the game's texts stay.
    lua6, _, _, log6, _ = started(before=lambda l, a, r: l.execute(
        'fake.texts.refuse = {"REGISTRY_FULL", "no spare capacity"}'))
    check(lua6.eval('TrueIntel._test.lines').state == 'failed' and lua6.globals().fake.writes == 0
          and 'Lines NOT applied: ensure refused (REGISTRY_FULL' in log6(), 'registry full: refused, nothing written')

    # A language change, then the registry refused for good (another mod took the spare place): the game's ids back,
    # the lines stop, one log line for the refusal.
    lua6b, at6b, recs6b, log6b, _ = started()
    lua6b.execute('fake.texts.registered = false; fake.texts.refuse = {"UNAVAILABLE", "switching"}; step(40)')
    lua6b.execute('fake.texts.refuse = {"REGISTRY_FULL", "no spare capacity"}; step(80)')
    check(lua6b.eval('TrueIntel._test.lines').state == 'failed'
          and u32_at(lua6b, row_at(at6b, recs6b, GUN, RELOAD) + 12) == 0xCE97302E
          and log6b().count('registering them again refused: ensure refused (REGISTRY_FULL') == 1,
          'texts lost, then refused for good: the game\'s ids, the lines stop')

    # Writes refused: the lines stay the game's, no error.
    lua7, _, _, log7, _ = started(before=lambda l, a, r: l.execute('fake.refuse_writes = true'))
    states = {L.state for L in lua7.eval('TrueIntel._test.lines').list.values()}
    check(states == {'failed'} and lua7.eval('TrueIntel.errors') == 0 and '12 failed' in log7(),
          'writes refused: every line failed, no error')

    # The armor scale's code moved out of reach (a patched byte): the armor lines stay the game's, the rest apply.
    lua8, _, _, log8, _ = started(before=lambda l, a, r: l.globals().fake.patch(0x19161D0, b'\xCC'), frames=40)
    lines8 = lua8.eval('TrueIntel._test.lines')
    check(lines8.state == 'applied' and len(lines8.list) == 7 and 'no armor rating scale' in log8(),
          'no armor scale: the five armor lines skipped, seven applied (%s, %d)' % (lines8.state, len(lines8.list)))

    # A required signature missing: not available, nothing written.
    lua9, _, _, _, status9 = started(before=lambda l, a, r: l.globals().fake.patch(0x11DA090, b'\xCC'), frames=40)
    check(status9().startswith('NOT AVAILABLE - signatures missing: customization')
          and lua9.globals().fake.writes == 0, 'passive_value missing: refused, nothing written')

    print('%d/%d' % (sum(ok), len(ok)))
    return all(ok)


if __name__ == '__main__':
    sys.exit(0 if run() else 1)
