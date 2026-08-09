"""Sustained-load soak of the GoForge component under wasmtime, with no jco involved.

Answers the one question that decides where the GC trap lives: does the component itself fail
under sustained dispatch, or only under the jco/Deno host?
"""

import sys
from types import SimpleNamespace
from wasmtime import Config, Engine, Store, WasiConfig, component

COMPONENT = sys.argv[1]
DISPATCHES = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
GOGC = sys.argv[3] if len(sys.argv) > 3 else None

REQUEST = '{"abi":"goforge.abi.v1","id":"soak","operation":"crypto.sha256","payload":{"data":""}}'

engine = Engine(Config())
store = Store(engine)

wasi = WasiConfig()
if GOGC:
    wasi.env = [("GOGC", GOGC)]
store.set_wasi(wasi)

linker = component.Linker(engine)
linker.add_wasip2()

comp = component.Component.from_file(engine, COMPONENT)
instance = linker.instantiate(store, comp)

iface = instance.get_export_index(store, "pointerbyte:goforge/operations@0.1.0")
assert iface is not None, "component does not export the operations interface"
dispatch = instance.get_func(store, instance.get_export_index(store, "dispatch", iface))
manifest = instance.get_func(store, instance.get_export_index(store, "manifest", iface))
assert dispatch is not None and manifest is not None, "missing dispatch/manifest export"

# Prove the instance is live and speaking the canonical contract before soaking it.
head = manifest(store)
assert '"abi":"goforge.abi.v1"' in head, head[:120]

# wasmtime-py reads record fields with getattr using the raw WIT names, so the
# carrier needs hyphenated attributes rather than a dict.
state = SimpleNamespace()
for field, value in (
    ("clock-checked", False),
    ("now-unix-milliseconds", 0),
    ("cancellation-checked", False),
    ("cancellation-token", ""),
    ("cancellation-requested", False),
):
    setattr(state, field, value)

first = dispatch(store, REQUEST, state)
expected = '"digest":"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="'
assert expected in first, first[:200]

completed = 0
try:
    for completed in range(1, DISPATCHES + 1):
        dispatch(store, REQUEST, state)
    print(f"OK {completed}")
except Exception as exc:  # noqa: BLE001 - the failure mode is what we are measuring
    print(f"TRAP {completed} :: {type(exc).__name__}: {str(exc)[:160]}")
