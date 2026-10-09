import json, os, pathlib

def home():
    p = pathlib.Path(os.environ.get("TWINSHIELD_HOME", pathlib.Path.home() / ".twinshield"))
    p.mkdir(parents=True, exist_ok=True)
    return p

def load(name, default):
    f = home() / name
    try: return json.loads(f.read_text())
    except (OSError, ValueError): return default

def save(name, data):
    f = home() / name
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(f)
