import os
import json
import time
import random
import string
import hmac
from functools import wraps

from flask import Flask, request, jsonify

app = Flask(__name__)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "neverpuze_admin_2026")
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_FILE = os.path.join(DATA_DIR, "keys.json")
LICENSES_FILE = os.path.join(DATA_DIR, "licenses.json")


def load_json(path, default=None):
    if default is None:
        default = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            auth = auth[7:]
        if not hmac.compare_digest(auth, ADMIN_SECRET):
            return jsonify({"ok": False, "msg": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


@app.route("/activate", methods=["POST"])
def activate():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid json"})

    key = body.get("key", "").strip().upper()
    hwid = body.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"ok": False, "msg": "missing key or hwid"})

    keys_db = load_json(KEYS_FILE)

    if key not in keys_db:
        return jsonify({"ok": False, "msg": "key not found"})

    stored = keys_db[key]

    if stored.get("hwid") is None:
        keys_db[key]["hwid"] = hwid
        save_json(KEYS_FILE, keys_db)
    elif stored["hwid"] != hwid:
        return jsonify({"ok": False, "msg": "key bound to different hwid"})

    return jsonify({"ok": True, "msg": "activated"})


@app.route("/checksub", methods=["POST"])
def checksub():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid json"})

    login = body.get("login", "").strip()
    if not login:
        return jsonify({"ok": False, "msg": "missing login"})

    licenses_db = load_json(LICENSES_FILE)

    if login in licenses_db:
        lic = licenses_db[login]
        return jsonify({
            "ok": True,
            "lifetime": lic.get("lifetime", False),
            "expires": lic.get("expires", 0),
        })

    return jsonify({"ok": False, "msg": "no subscription"})


@app.route("/admin/genkey", methods=["POST"])
@require_admin
def admin_genkey():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid json"})

    count = body.get("count", 1)
    if not isinstance(count, int) or count < 1 or count > 100:
        return jsonify({"ok": False, "msg": "count must be 1-100"})

    keys_db = load_json(KEYS_FILE)
    generated = []
    for _ in range(count):
        key = generate_key()
        keys_db[key] = {"hwid": None, "created": int(time.time())}
        generated.append(key)
    save_json(KEYS_FILE, keys_db)

    return jsonify({"ok": True, "keys": generated})


@app.route("/admin/delkey", methods=["POST"])
@require_admin
def admin_delkey():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid json"})

    key = body.get("key", "").strip().upper()
    keys_db = load_json(KEYS_FILE)

    if key in keys_db:
        del keys_db[key]
        save_json(KEYS_FILE, keys_db)
        return jsonify({"ok": True, "msg": "deleted"})

    return jsonify({"ok": False, "msg": "key not found"})


@app.route("/admin/keys", methods=["GET"])
@require_admin
def admin_keys():
    keys_db = load_json(KEYS_FILE)
    result = []
    for key, info in keys_db.items():
        hwid = info.get("hwid")
        result.append({
            "key": key,
            "hwid": hwid,
            "created": info.get("created", 0),
        })
    return jsonify({"ok": True, "keys": result, "count": len(result)})


@app.route("/admin/setsub", methods=["POST"])
@require_admin
def admin_setsub():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid json"})

    login = body.get("login", "").strip()
    duration = body.get("duration", "").strip()

    if not login or not duration:
        return jsonify({"ok": False, "msg": "missing login or duration"})

    licenses_db = load_json(LICENSES_FILE)

    if duration.lower() == "lifetime":
        licenses_db[login] = {"lifetime": True, "expires": 0}
    else:
        seconds = parse_duration(duration)
        if seconds is None:
            return jsonify({"ok": False, "msg": "invalid duration format"})
        licenses_db[login] = {"lifetime": False, "expires": int(time.time()) + seconds}

    save_json(LICENSES_FILE, licenses_db)

    lic = licenses_db[login]
    return jsonify({
        "ok": True,
        "login": login,
        "lifetime": lic["lifetime"],
        "expires": lic["expires"],
    })


@app.route("/admin/rmsub", methods=["POST"])
@require_admin
def admin_rmsub():
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid json"})

    login = body.get("login", "").strip()
    licenses_db = load_json(LICENSES_FILE)

    if login in licenses_db:
        del licenses_db[login]
        save_json(LICENSES_FILE, licenses_db)
        return jsonify({"ok": True, "msg": "subscription removed"})

    return jsonify({"ok": False, "msg": "subscription not found"})


@app.route("/admin/licenses", methods=["GET"])
@require_admin
def admin_licenses():
    licenses_db = load_json(LICENSES_FILE)
    result = []
    for login, lic in licenses_db.items():
        result.append({
            "login": login,
            "lifetime": lic.get("lifetime", False),
            "expires": lic.get("expires", 0),
        })
    return jsonify({"ok": True, "licenses": result, "count": len(result)})


def generate_key():
    parts = []
    for _ in range(4):
        part = "".join(random.choices(string.hexdigits[:16].upper(), k=4))
        parts.append(part)
    return "-".join(parts)


def parse_duration(text):
    import re
    match = re.fullmatch(r"(\d+)\s*([smhd])?", text.strip().lower())
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2) or "m"
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return amount * units[unit]


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
