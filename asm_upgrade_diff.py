#!/usr/bin/env python3
r"""
asm_upgrade_diff.py - Snapshot every ASM policy on one or more BIG-IPs before and
after an upgrade, then produce an HTML diff report.

Workflow
--------
  1. Before the upgrade:
       ./asm_upgrade_diff.py export --phase pre  --host 10.1.1.245 -u admin
  2. After the upgrade:
       ./asm_upgrade_diff.py export --phase post --host 10.1.1.245 -u admin
     (the report is generated automatically when pre-upgrade data exists)
  3. Re-generate the report at any time:
       ./asm_upgrade_diff.py report

  Multiple devices:  --hosts-file devices.txt   (one host/IP per line, '#' comments OK)
  Password:          -p/--password, or $BIGIP_PASSWORD, or interactive prompt.

Noise filter (what to ignore when deciding if a policy changed "materially")
----------------------------------------------------------------------------
  --noise-file FILE     load rules from a file (repeatable)
  --ignore-tag NAME     add one element/key rule  (same as a 'NAME' line in a file)
  --ignore-attr NAME    add one attribute rule    (same as an '@NAME' line in a file)
  --no-default-noise    drop the built-in rules and use only yours

  Noise file format: one rule per line, blank lines and '#' comments ignored.
  '*' and '?' wildcards work in every rule except re: rules.
    timestamp                 element (XML) or key (JSON) with this name, anywhere
    urls/url                  element at this path below the policy root
    @bigip_version            attribute with this name, on any element
    url@last_updated          attribute only on the named element (or path)
    re:^\s*<staging_period    drop normalized lines matching this regex

  Example noise.txt:
    # upgrade bookkeeping
    *_timestamp
    @last_*
    attack_signatures         # ignore signature list churn from ASU differences

Authentication uses the iControl REST token method:
  POST /mgmt/shared/authn/login  ->  X-F5-Auth-Token header on every request.

Output layout (default ./asm_snapshots):
  <outdir>/<device>/pre/manifest.json          version, hostname, policy list, hashes
  <outdir>/<device>/pre/policies/<policy>.xml  exported policy
  <outdir>/<device>/post/...                   same, after the upgrade
  <outdir>/report.html                         summary + per-policy diffs
  <outdir>/report.json                         machine-readable summary
  <outdir>/diffs/<device>/<policy>.diff        full unified diffs

Requires: Python 3.8+, requests  (pip install requests)
"""

import argparse
import concurrent.futures
import datetime as dt
import difflib
import getpass
import hashlib
import html
import json
import logging
import os
import re
import shutil
import sys
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from fnmatch import fnmatchcase
from pathlib import Path

try:
    import requests
    import urllib3
except ImportError:  # pragma: no cover
    sys.exit("This script needs the 'requests' package:  pip install requests")

LOG = logging.getLogger("asm_upgrade_diff")
CHUNK_SIZE = 1024 * 1024  # ASM file-transfer endpoint serves at most 1 MB per request

# Built-in noise rules: fields that change on every export or every upgrade and
# are not policy content. Same syntax as --noise (see module docstring).
DEFAULT_NOISE = [
    # XML export
    "policy_version", "timestamp", "last_update_micros", "last_updated",
    "device_name", "last_change", "export_time", "integrity_check",
    "@bigip_version", "@integrity_check", "@export_time",
    # JSON export
    "lastUpdateMicros", "creationDatetime", "modifiedDatetime", "versionDatetime",
    "versionDeviceName", "versionLastChange", "versionPolicyName", "versionLastChangeUser",
    "exportTime", "exportedBy",
]


class BigIPError(Exception):
    pass


class NoiseFilter:
    """Rules deciding which parts of an export are ignored when diffing."""

    def __init__(self):
        self.rules = []      # (rule text, origin)
        self.tags = []       # element / key name globs
        self.paths = []      # element / key path globs (relative to policy root)
        self.attrs = []      # (element name-or-path glob or None, attribute glob)
        self.regexes = []    # compiled line regexes

    def add(self, rule, origin="cli"):
        rule = rule.strip()
        if not rule or rule.startswith("#"):
            return
        if rule.startswith("re:"):
            try:
                self.regexes.append(re.compile(rule[3:]))
            except re.error as e:
                raise ValueError(f"bad regex in noise rule {rule!r} ({origin}): {e}") from e
        elif "@" in rule:
            target, attr = rule.split("@", 1)
            if not attr:
                raise ValueError(f"noise rule {rule!r} ({origin}) has no attribute name after '@'")
            self.attrs.append((target.strip("/") or None, attr))
        elif "/" in rule.strip("/"):
            self.paths.append(rule.strip("/"))
        else:
            self.tags.append(rule.strip("/"))
        self.rules.append((rule, origin))

    def add_file(self, path):
        p = Path(path)
        if not p.is_file():
            raise ValueError(f"noise filter file not found: {path}")
        for n, line in enumerate(p.read_text().splitlines(), 1):
            self.add(line.split(" #", 1)[0] if not line.lstrip().startswith("re:") else line,
                     origin=f"{p.name}:{n}")

    def drop_element(self, tag, path):
        return any(fnmatchcase(tag, g) for g in self.tags) or \
            any(fnmatchcase(path, g) for g in self.paths)

    def drop_attr(self, tag, path, attr):
        return any((t is None or fnmatchcase(tag, t) or fnmatchcase(path, t))
                   and fnmatchcase(attr, a) for t, a in self.attrs)

    def drop_line(self, line):
        return any(r.search(line) for r in self.regexes)

    def filter_lines(self, lines):
        return [l for l in lines if not self.drop_line(l)] if self.regexes else lines


# --------------------------------------------------------------------------- #
# iControl REST client (token auth)
# --------------------------------------------------------------------------- #
class BigIP:
    def __init__(self, host, username, password, verify=False,
                 login_provider="tmos", timeout=60, token_timeout=3600):
        self.host = host
        self.base = f"https://{host}"
        self.username = username
        self.password = password
        self.login_provider = login_provider
        self.timeout = timeout
        self.token_timeout = token_timeout
        self.token = None
        self.s = requests.Session()
        self.s.verify = verify
        self.s.headers.update({"Content-Type": "application/json"})

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *exc):
        self.logout()

    # -- auth ---------------------------------------------------------------
    def login(self):
        self.s.headers.pop("X-F5-Auth-Token", None)
        try:
            r = self.s.post(f"{self.base}/mgmt/shared/authn/login",
                            json={"username": self.username,
                                  "password": self.password,
                                  "loginProviderName": self.login_provider},
                            timeout=self.timeout)
        except requests.RequestException as e:
            raise BigIPError(f"cannot reach {self.host}: {e}") from e
        if r.status_code != 200:
            raise BigIPError(f"login failed (HTTP {r.status_code}): {r.text[:300]}")
        try:
            self.token = r.json()["token"]["token"]
        except (ValueError, KeyError) as e:
            raise BigIPError(f"unexpected login response: {r.text[:300]}") from e
        self.s.headers["X-F5-Auth-Token"] = self.token
        # Default token life is 1200s; extend so large exports don't expire mid-run.
        try:
            self.s.patch(f"{self.base}/mgmt/shared/authz/tokens/{self.token}",
                         json={"timeout": self.token_timeout}, timeout=self.timeout)
        except requests.RequestException:
            LOG.debug("%s: could not extend token timeout", self.host)

    def logout(self):
        if self.token:
            try:
                self.s.delete(f"{self.base}/mgmt/shared/authz/tokens/{self.token}",
                              timeout=self.timeout)
            except requests.RequestException:
                pass
            self.token = None

    # -- requests -----------------------------------------------------------
    def request(self, method, path, retry_auth=True, **kw):
        kw.setdefault("timeout", self.timeout)
        try:
            r = self.s.request(method, self.base + path, **kw)
        except requests.RequestException as e:
            raise BigIPError(f"{method} {path}: {e}") from e
        if r.status_code == 401 and retry_auth:
            LOG.info("%s: token rejected, logging in again", self.host)
            self.login()
            return self.request(method, path, retry_auth=False, **kw)
        if r.status_code >= 400:
            raise BigIPError(f"{method} {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r

    def get_json(self, path, **kw):
        return self.request("GET", path, **kw).json()

    # -- device facts -------------------------------------------------------
    def get_version(self):
        data = self.get_json("/mgmt/tm/sys/version")
        for entry in data.get("entries", {}).values():
            ne = entry.get("nestedStats", {}).get("entries", {})
            g = lambda k: ne.get(k, {}).get("description", "")  # noqa: E731
            return {"product": g("Product"), "version": g("Version"),
                    "build": g("Build"), "edition": g("Edition"), "date": g("Date")}
        return {}

    def get_hostname(self):
        try:
            return self.get_json("/mgmt/tm/sys/global-settings").get("hostname", "")
        except BigIPError:
            return ""

    def list_policies(self):
        data = self.get_json("/mgmt/tm/asm/policies",
                             params={"$select": "id,name,fullPath,type,active,enforcementMode"})
        return data.get("items", [])

    # -- export -------------------------------------------------------------
    def export_policy(self, policy_id, remote_name, dest, fmt="xml", poll_timeout=600):
        body = {"filename": remote_name,
                "policyReference": {"link": f"https://localhost/mgmt/tm/asm/policies/{policy_id}"}}
        if fmt == "json":
            body["format"] = "json"
        task = self.request("POST", "/mgmt/tm/asm/tasks/export-policy", json=body).json()
        task_id = task["id"]
        task_path = f"/mgmt/tm/asm/tasks/export-policy/{task_id}"
        deadline = time.time() + poll_timeout
        delay = 1.0
        while True:
            t = self.get_json(task_path)
            status = t.get("status", "")
            if status == "COMPLETED":
                break
            if status in ("FAILURE", "FAILED"):
                msg = t.get("result", {}).get("message") or json.dumps(t)[:300]
                raise BigIPError(f"export task failed: {msg}")
            if time.time() > deadline:
                raise BigIPError(f"export task {task_id} timed out (last status {status!r})")
            time.sleep(delay)
            delay = min(delay * 1.5, 5)
        self.download(remote_name, dest)
        try:  # tidy up the task record; the file itself stays in /var/ts/var/rest
            self.request("DELETE", task_path, retry_auth=False)
        except BigIPError:
            pass

    def download(self, remote_name, dest):
        """Chunked download from /mgmt/tm/asm/file-transfer/downloads/."""
        path = f"/mgmt/tm/asm/file-transfer/downloads/{remote_name}"
        tmp = Path(str(dest) + ".part")
        start, total = 0, 0
        with open(tmp, "wb") as fh:
            while True:
                end = start + CHUNK_SIZE - 1
                headers = {"Content-Type": "application/octet-stream",
                           "Content-Range": f"{start}-{end}/{total}"}
                r = self.request("GET", path, headers=headers)
                fh.write(r.content)
                m = re.match(r"\s*(\d+)-(\d+)/(\d+)", r.headers.get("Content-Range", ""))
                if not m:
                    break  # whole file came back in one response
                _, rend, total = map(int, m.groups())
                if rend + 1 >= total:
                    break
                start = rend + 1
        tmp.replace(dest)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "unnamed"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def load_hosts(args):
    hosts = list(args.host or [])
    if args.hosts_file:
        for line in Path(args.hosts_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                hosts.append(re.split(r"[\s,]+", line)[0])
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def fmt_version(v):
    if not v:
        return "unknown"
    s = v.get("version", "?")
    if v.get("build"):
        s += f" build {v['build']}"
    if v.get("edition") and v["edition"] != "Final":
        s += f" ({v['edition']})"
    return s


# --------------------------------------------------------------------------- #
# Export phase
# --------------------------------------------------------------------------- #
def export_device(host, args, password):
    devdir = Path(args.outdir) / safe_name(host) / args.phase
    if (devdir / "manifest.json").exists():
        if not args.force:
            raise BigIPError(f"{devdir} already has a {args.phase} snapshot; "
                             f"use --force to overwrite it")
        shutil.rmtree(devdir)
    pol_dir = devdir / "policies"
    pol_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"host": host, "phase": args.phase, "collected_at": now_iso(),
                "format": args.format, "hostname": "", "version": {},
                "policy_count": None, "policies": [], "errors": []}
    ext = "json" if args.format == "json" else "xml"
    try:
        with BigIP(host, args.username, password, verify=args.verify_arg,
                   login_provider=args.login_provider, timeout=args.timeout) as bip:
            manifest["version"] = bip.get_version()
            manifest["hostname"] = bip.get_hostname()
            LOG.info("%s: %s, BIG-IP %s", host, manifest["hostname"] or "?",
                     fmt_version(manifest["version"]))
            policies = sorted(bip.list_policies(), key=lambda p: p.get("fullPath", ""))
            manifest["policy_count"] = len(policies)
            LOG.info("%s: %d ASM policies found", host, len(policies))
            for i, p in enumerate(policies, 1):
                full = p.get("fullPath") or p.get("name")
                entry = {k: p.get(k) for k in ("id", "name", "fullPath", "type",
                                                "active", "enforcementMode")}
                entry.update(file=None, sha256=None, error=None)
                local = pol_dir / f"{safe_name(full)}.{ext}"
                remote = f"asmdiff_{args.phase}_{p['id']}.{ext}"
                try:
                    LOG.info("%s: [%d/%d] exporting %s", host, i, len(policies), full)
                    bip.export_policy(p["id"], remote, local, fmt=args.format,
                                      poll_timeout=args.task_timeout)
                    entry["file"] = str(local.relative_to(devdir))
                    entry["sha256"] = sha256(local)
                except BigIPError as e:
                    entry["error"] = str(e)
                    manifest["errors"].append(f"{full}: {e}")
                    LOG.error("%s: %s: %s", host, full, e)
                manifest["policies"].append(entry)
    except BigIPError as e:
        manifest["errors"].append(str(e))
        LOG.error("%s: %s", host, e)

    (devdir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def cmd_export(args):
    hosts = load_hosts(args)
    if not hosts:
        sys.exit("No devices given: use --host and/or --hosts-file")
    password = args.password or os.environ.get("BIGIP_PASSWORD") or \
        getpass.getpass(f"Password for {args.username}: ")

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futs = {pool.submit(export_device, h, args, password): h for h in hosts}
        for fut in concurrent.futures.as_completed(futs):
            h = futs[fut]
            try:
                results[h] = fut.result()
            except Exception as e:  # noqa: BLE001
                LOG.error("%s: %s", h, e)
                results[h] = None

    print(f"\n{args.phase.upper()} export summary")
    for h in hosts:
        m = results.get(h)
        if not m:
            print(f"  {h:<30} FAILED (see log)")
        else:
            ok = sum(1 for p in m["policies"] if p["file"])
            print(f"  {h:<30} {fmt_version(m['version']):<28} "
                  f"{ok}/{m['policy_count'] or 0} policies exported"
                  + (f", {len(m['errors'])} error(s)" if m["errors"] else ""))

    if args.phase == "post" and not args.no_report:
        cmd_report(args)
    return 0 if all(results.get(h) and not results[h]["errors"] for h in hosts) else 1


# --------------------------------------------------------------------------- #
# Normalisation + diff
# --------------------------------------------------------------------------- #
def canon_xml(path, noise, sort_siblings):
    root = ET.parse(path).getroot()

    def strip(el, el_path):
        for a in list(el.attrib):
            if noise.drop_attr(el.tag, el_path, a):
                del el.attrib[a]
        for child in list(el):
            child_path = f"{el_path}/{child.tag}" if el_path else child.tag
            if noise.drop_element(child.tag, child_path):
                el.remove(child)
            else:
                strip(child, child_path)

    def clean_text(t):
        return (t or "").strip().replace("\r", "").replace("\n", "\\n")

    def render(el, depth):
        ind = "  " * depth
        attrs = "".join(f' {k}="{v}"' for k, v in sorted(el.attrib.items()))
        text = clean_text(el.text)
        children = list(el)
        if not children:
            return [f"{ind}<{el.tag}{attrs}>{text}</{el.tag}>" if text
                    else f"{ind}<{el.tag}{attrs}/>"]
        out = [f"{ind}<{el.tag}{attrs}>"]
        if text:
            out.append(f"{ind}  {text}")
        blocks = [render(c, depth + 1) for c in children]
        if sort_siblings:
            blocks.sort(key="\n".join)
        for b in blocks:
            out.extend(b)
        out.append(f"{ind}</{el.tag}>")
        return out

    strip(root, "")
    root_blocks = [(c.tag, noise.filter_lines(render(c, 1))) for c in root]
    if sort_siblings:
        root_blocks.sort(key=lambda tb: "\n".join(tb[1]))
    attrs = "".join(f' {k}="{v}"' for k, v in sorted(root.attrib.items()))
    lines = noise.filter_lines([f"<{root.tag}{attrs}>"])
    sections = defaultdict(list)
    for tag, block in root_blocks:
        lines.extend(block)
        sections[tag].append("\n".join(block))
    lines.extend(noise.filter_lines([f"</{root.tag}>"]))
    if root.attrib:
        sections["(policy attributes)"].append(attrs)
    return lines, {k: "\n".join(v) for k, v in sections.items()}


def canon_json(path, noise, sort_lists):
    data = json.loads(Path(path).read_text())

    def clean(o, o_path):
        if isinstance(o, dict):
            out = {}
            for k, v in o.items():
                k_path = f"{o_path}/{k}" if o_path else k
                if not noise.drop_element(k, k_path):
                    out[k] = clean(v, k_path)
            return out
        if isinstance(o, list):
            items = [clean(i, o_path) for i in o]
            if sort_lists:
                items.sort(key=lambda x: json.dumps(x, sort_keys=True))
            return items
        return o

    # paths are relative to the policy object, matching the XML convention
    if isinstance(data, dict) and isinstance(data.get("policy"), dict):
        data = {**data, "policy": clean(data["policy"], "")}
        data = {k: (v if k == "policy" else clean(v, k)) for k, v in data.items()}
        pol = data["policy"]
    else:
        data = clean(data, "")
        pol = data if isinstance(data, dict) else {}
    lines = noise.filter_lines(json.dumps(data, indent=2, sort_keys=True).splitlines())
    sections = {k: "\n".join(noise.filter_lines(json.dumps(v, indent=2, sort_keys=True).splitlines()))
                for k, v in pol.items()}
    return lines, sections


def canonicalize(path, opts):
    if str(path).endswith(".json"):
        return canon_json(path, opts["noise"], opts["sort"])
    return canon_xml(path, opts["noise"], opts["sort"])


def compare_policy(pre_path, post_path, opts):
    if sha256(pre_path) == sha256(post_path):
        return {"status": "identical"}
    try:
        pre_lines, pre_sec = canonicalize(pre_path, opts)
        post_lines, post_sec = canonicalize(post_path, opts)
    except (ET.ParseError, json.JSONDecodeError) as e:
        return {"status": "error", "error": f"could not parse export: {e}"}
    if pre_lines == post_lines:
        return {"status": "cosmetic"}
    diff = list(difflib.unified_diff(pre_lines, post_lines, "pre-upgrade",
                                     "post-upgrade", n=opts["context"], lineterm=""))
    added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
    changed = sorted(k for k in set(pre_sec) | set(post_sec)
                     if pre_sec.get(k) != post_sec.get(k))
    return {"status": "material", "diff": diff, "added": added,
            "removed": removed, "sections": changed}


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
STATUS_LABEL = {
    "identical": ("Identical", "ok"),
    "cosmetic": ("No material change", "ok"),
    "material": ("Material change", "bad"),
    "missing_post": ("Missing after upgrade", "bad"),
    "new_post": ("New after upgrade", "warn"),
    "error": ("Export / parse error", "bad"),
}


def load_manifest(devdir, phase):
    p = devdir / phase / "manifest.json"
    return json.loads(p.read_text()) if p.exists() else None


def build_results(outdir, opts):
    devices = []
    for devdir in sorted(p for p in Path(outdir).iterdir() if p.is_dir() and p.name != "diffs"):
        pre, post = load_manifest(devdir, "pre"), load_manifest(devdir, "post")
        if not pre and not post:
            continue
        dev = {"key": devdir.name, "host": (pre or post)["host"],
               "hostname": (post or pre).get("hostname", ""),
               "pre": pre, "post": post, "policies": [], "notes": []}
        devices.append(dev)
        if not pre or not post:
            dev["notes"].append(f"No {'pre' if not pre else 'post'}-upgrade snapshot yet.")
            continue
        for m, label in ((pre, "pre"), (post, "post")):
            for err in m.get("errors", []):
                dev["notes"].append(f"{label}-upgrade: {err}")
        if pre.get("version") and pre.get("version") == post.get("version"):
            dev["notes"].append("Software version is the same before and after; "
                                "the upgrade may not have been applied yet.")

        pre_pols = {p["fullPath"]: p for p in pre["policies"]}
        post_pols = {p["fullPath"]: p for p in post["policies"]}
        for name in sorted(set(pre_pols) | set(post_pols)):
            a, b = pre_pols.get(name), post_pols.get(name)
            row = {"name": name, "anchor": f"{safe_name(devdir.name)}--{safe_name(name)}"}
            if not b:
                row["status"] = "missing_post"
            elif not a:
                row["status"] = "new_post"
            elif a.get("error") or b.get("error"):
                row.update(status="error", error=a.get("error") or b.get("error"))
            else:
                row.update(compare_policy(devdir / "pre" / a["file"],
                                          devdir / "post" / b["file"], opts))
            if row.get("diff"):
                dpath = Path(outdir) / "diffs" / devdir.name / f"{safe_name(name)}.diff"
                dpath.parent.mkdir(parents=True, exist_ok=True)
                dpath.write_text("\n".join(row["diff"]) + "\n")
                row["diff_file"] = str(dpath.relative_to(outdir))
            dev["policies"].append(row)

        st = [r["status"] for r in dev["policies"]]
        dev["pre_count"], dev["post_count"] = pre.get("policy_count"), post.get("policy_count")
        dev["count_match"] = dev["pre_count"] == dev["post_count"] and \
            "missing_post" not in st and "new_post" not in st
        dev["material"] = st.count("material")
        dev["errors"] = st.count("error")
    return devices


def device_ok(d):
    return bool(d["pre"] and d["post"] and d.get("count_match")
                and not d.get("material") and not d.get("errors")
                and not d["pre"].get("errors") and not d["post"].get("errors"))


CSS = """
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--muted:#5d6678;--line:#dde1e8;
--ok:#1f7a3f;--okbg:#e5f4ea;--bad:#b42318;--badbg:#fdecea;--warn:#8a5a00;--warnbg:#fff4d6;
--add:#e6ffec;--addfg:#116329;--del:#ffebe9;--delfg:#82071e;--hunk:#ddf4ff;--accent:#0b62c4}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e4e7ee;--muted:#9aa3b5;
--line:#2a303c;--ok:#5fd38a;--okbg:#14301f;--bad:#ff7b72;--badbg:#3a1614;--warn:#f2c14e;--warnbg:#36290a;
--add:#12301d;--addfg:#7ee2a0;--del:#3a1418;--delfg:#ffa198;--hunk:#10283f;--accent:#58a6ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px}h3{font-size:15px;margin:20px 0 6px}
.muted{color:var(--muted)}a{color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin:12px 0}
.banner{font-size:16px;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:12px}
.tile{border:1px solid var(--line);border-radius:6px;padding:10px}.tile b{display:block;font-size:22px}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
.ok{background:var(--okbg);color:var(--ok)}.bad{background:var(--badbg);color:var(--bad)}
.warn{background:var(--warnbg);color:var(--warn)}
ul.notes{margin:6px 0;padding-left:20px}
details{border:1px solid var(--line);border-radius:6px;margin:10px 0;background:var(--card)}
summary{cursor:pointer;padding:8px 12px;font-weight:600}
pre.diff{margin:0;padding:8px 0;overflow-x:auto;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
border-top:1px solid var(--line)}
pre.diff span{display:block;padding:0 12px;white-space:pre}
.add{background:var(--add);color:var(--addfg)}.del{background:var(--del);color:var(--delfg)}
.hunk{background:var(--hunk);color:var(--muted)}.hdr{color:var(--muted);font-weight:600}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
"""


def pill(text, cls):
    return f'<span class="pill {cls}">{html.escape(text)}</span>'


def render_diff(lines, limit):
    out = []
    for l in lines[:limit]:
        if l.startswith(("+++", "---")):
            cls = "hdr"
        elif l.startswith("@@"):
            cls = "hunk"
        elif l.startswith("+"):
            cls = "add"
        elif l.startswith("-"):
            cls = "del"
        else:
            cls = ""
        out.append(f'<span class="{cls}">{html.escape(l) or " "}</span>')
    return "".join(out)


def write_report(devices, outdir, opts):
    e = html.escape
    complete = [d for d in devices if d["pre"] and d["post"]]
    n_mismatch = sum(1 for d in complete if not d["count_match"])
    n_material = sum(d["material"] for d in complete)
    n_errors = sum(d["errors"] for d in complete) + \
        sum(1 for d in devices if any(m and m.get("errors") for m in (d["pre"], d["post"])))
    all_ok = devices and all(device_ok(d) for d in devices)

    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
         f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>ASM Upgrade Diff</title><style>{CSS}</style></head><body><main>",
         "<h1>ASM policy upgrade comparison</h1>",
         f"<div class='muted'>Generated {e(now_iso())} from <code>{e(str(Path(outdir).resolve()))}</code></div>"]

    # ---- overall summary ----
    verdict = ("All devices: policy counts match and no material policy differences."
               if all_ok else "Attention needed: see the flagged items below.")
    h.append(f"<div class='card'><div class='banner'>{pill('PASS' if all_ok else 'REVIEW', 'ok' if all_ok else 'bad')} "
             f"{e(verdict)}</div><div class='tiles'>"
             f"<div class='tile'><b>{len(complete)}/{len(devices)}</b>devices with pre + post data</div>"
             f"<div class='tile'><b>{n_mismatch}</b>devices with policy count mismatch</div>"
             f"<div class='tile'><b>{n_material}</b>policies with material differences</div>"
             f"<div class='tile'><b>{n_errors}</b>export / parse errors</div></div></div>")

    # ---- device summary table ----
    h.append("<h2>Device summary</h2><div class='card wrap'><table><tr><th>Device</th><th>Version before → after</th>"
             "<th>Policies before / after</th><th>Count</th><th>Material diffs</th><th>Status</th></tr>")
    for d in devices:
        pre_v = fmt_version(d["pre"]["version"]) if d["pre"] else "—"
        post_v = fmt_version(d["post"]["version"]) if d["post"] else "—"
        name = e(d["host"]) + (f"<div class='muted'>{e(d['hostname'])}</div>" if d["hostname"] else "")
        if not (d["pre"] and d["post"]):
            h.append(f"<tr><td><a href='#dev-{e(d['key'])}'>{name}</a></td><td>{e(pre_v)} → {e(post_v)}</td>"
                     f"<td>—</td><td>—</td><td>—</td><td>{pill('Incomplete', 'warn')}</td></tr>")
            continue
        count = pill("Match", "ok") if d["count_match"] else pill("Mismatch", "bad")
        mat = d["material"]
        mat_html = (f"<a href='#dev-{e(d['key'])}'>{mat}</a>" if mat else "0")
        h.append(f"<tr><td><a href='#dev-{e(d['key'])}'>{name}</a></td><td>{e(pre_v)} → {e(post_v)}</td>"
                 f"<td>{d['pre_count']} / {d['post_count']}</td><td>{count}</td><td>{mat_html}</td>"
                 f"<td>{pill('OK', 'ok') if device_ok(d) else pill('Review', 'bad')}</td></tr>")
    h.append("</table></div>")

    # ---- flagged policy index ----
    flagged = [(d, r) for d in devices for r in d["policies"]
               if r["status"] in ("material", "missing_post", "new_post", "error")]
    if flagged:
        h.append("<h2>Policies needing review</h2><div class='card wrap'><table>"
                 "<tr><th>Device</th><th>Policy</th><th>Result</th><th>Changed sections</th></tr>")
        for d, r in flagged:
            lbl, cls = STATUS_LABEL[r["status"]]
            secs = ", ".join(r.get("sections", [])[:8]) + (" …" if len(r.get("sections", [])) > 8 else "")
            h.append(f"<tr><td>{e(d['host'])}</td><td><a href='#{e(r['anchor'])}'>{e(r['name'])}</a></td>"
                     f"<td>{pill(lbl, cls)}</td><td><code>{e(secs)}</code></td></tr>")
        h.append("</table></div>")

    # ---- per-device detail ----
    h.append("<h2>Details</h2>")
    for d in devices:
        h.append(f"<div class='card' id='dev-{e(d['key'])}'><h3>{e(d['host'])}"
                 f"{' — ' + e(d['hostname']) if d['hostname'] else ''}</h3>")
        for phase in ("pre", "post"):
            m = d[phase]
            if m:
                h.append(f"<div class='muted'>{phase}-upgrade: {e(fmt_version(m['version']))}, "
                         f"{m.get('policy_count')} policies, collected {e(m['collected_at'])}</div>")
        if d["notes"]:
            h.append("<ul class='notes'>" + "".join(f"<li>{e(n)}</li>" for n in d["notes"]) + "</ul>")
        if d["policies"]:
            h.append("<div class='wrap'><table><tr><th>Policy</th><th>Result</th><th>+/− lines</th></tr>")
            for r in d["policies"]:
                lbl, cls = STATUS_LABEL[r["status"]]
                name = (f"<a href='#{e(r['anchor'])}'>{e(r['name'])}</a>" if r["status"] in ("material", "error")
                        else e(r["name"]))
                pm = f"+{r['added']} / −{r['removed']}" if r["status"] == "material" else ""
                h.append(f"<tr><td>{name}</td><td>{pill(lbl, cls)}</td><td>{pm}</td></tr>")
            h.append("</table></div>")
        for r in d["policies"]:
            if r["status"] == "error":
                h.append(f"<details open id='{e(r['anchor'])}'><summary>{e(r['name'])} — error</summary>"
                         f"<pre class='diff'><span>{e(r.get('error', ''))}</span></pre></details>")
            elif r["status"] == "material":
                more = ""
                if len(r["diff"]) > opts["max_lines"]:
                    more = (f"<div class='muted' style='padding:6px 12px'>Showing first {opts['max_lines']} of "
                            f"{len(r['diff'])} diff lines.</div>")
                h.append(f"<details open id='{e(r['anchor'])}'><summary>{e(r['name'])} — "
                         f"+{r['added']} / −{r['removed']} lines; sections: "
                         f"{e(', '.join(r['sections']) or 'n/a')}</summary>"
                         f"<div class='muted' style='padding:0 12px 6px'>Full diff: "
                         f"<a href='{e(r['diff_file'])}'>{e(r['diff_file'])}</a></div>{more}"
                         f"<pre class='diff'>{render_diff(r['diff'], opts['max_lines'])}</pre></details>")
        h.append("</div>")

    by_origin = defaultdict(list)
    for rule, origin in opts["noise"].rules:
        by_origin[origin.split(":")[0]].append(rule)
    rule_rows = "".join(f"<tr><td>{e(o)}</td><td><code>{e('  ·  '.join(r))}</code></td></tr>"
                        for o, r in by_origin.items()) or "<tr><td colspan='2'>none</td></tr>"
    h.append(f"<div class='card muted'><b>How “material” is decided.</b> Each export is normalised before "
             f"comparison (attribute order canonicalised, whitespace trimmed"
             f"{', sibling elements sorted' if opts['sort'] else ''}) and then these noise-filter rules "
             f"are removed. “No material change” means the raw files differ only in filtered content. "
             f"Add rules with <code>--noise-file</code>.<div class='wrap' style='margin-top:8px'><table>"
             f"<tr><th>Source</th><th>Rules</th></tr>{rule_rows}</table></div></div>")
    h.append("</main></body></html>")

    out = Path(outdir) / "report.html"
    out.write_text("".join(h), encoding="utf-8")

    summary = {"generated_at": now_iso(), "overall_ok": bool(all_ok),
               "noise_rules": [{"rule": r, "source": o} for r, o in opts["noise"].rules],
               "devices": [
        {"host": d["host"], "hostname": d["hostname"],
         "version_pre": d["pre"] and d["pre"]["version"], "version_post": d["post"] and d["post"]["version"],
         "policy_count_pre": d.get("pre_count"), "policy_count_post": d.get("post_count"),
         "count_match": d.get("count_match"), "ok": device_ok(d), "notes": d["notes"],
         "policies": [{k: v for k, v in r.items() if k not in ("diff", "anchor")} for r in d["policies"]]}
        for d in devices]}
    (Path(outdir) / "report.json").write_text(json.dumps(summary, indent=2))
    return out, bool(all_ok)


def build_noise(args):
    noise = NoiseFilter()
    try:
        if not args.no_default_noise:
            for r in DEFAULT_NOISE:
                noise.add(r, origin="built-in")
        for f in args.noise_file or []:
            noise.add_file(f)
        for t in args.ignore_tag or []:
            noise.add(t, origin="--ignore-tag")
        for a in args.ignore_attr or []:
            noise.add("@" + a.lstrip("@"), origin="--ignore-attr")
    except ValueError as e:
        sys.exit(f"Noise filter error: {e}")
    return noise


def report_opts(args):
    return {"noise": build_noise(args), "sort": not args.keep_order,
            "context": args.context, "max_lines": args.max_diff_lines}


def cmd_report(args):
    if not Path(args.outdir).is_dir():
        sys.exit(f"Output directory {args.outdir} not found")
    opts = report_opts(args)
    devices = build_results(args.outdir, opts)
    if not devices:
        sys.exit(f"No snapshots found under {args.outdir}")
    path, ok = write_report(devices, args.outdir, opts)
    print(f"\nReport: {path.resolve()}  ->  {'PASS' if ok else 'REVIEW NEEDED'}")
    return 0 if ok else 2


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-o", "--outdir", default="asm_snapshots",
                        help="snapshot/report directory (default: ./asm_snapshots)")
    common.add_argument("-v", "--verbose", action="store_true")

    rep = argparse.ArgumentParser(add_help=False)
    rep.add_argument("--noise-file", action="append", metavar="FILE",
                     help="file of noise-filter rules, one per line (repeatable); rule syntax is in the script header")
    rep.add_argument("--no-default-noise", action="store_true",
                     help="don't apply the built-in noise rules")
    rep.add_argument("--ignore-tag", action="append", metavar="NAME",
                     help="extra XML element / JSON key to ignore when diffing (repeatable)")
    rep.add_argument("--ignore-attr", action="append", metavar="NAME",
                     help="extra XML attribute to ignore when diffing (repeatable)")
    rep.add_argument("--keep-order", action="store_true",
                     help="don't sort sibling elements before diffing (order-sensitive diff)")
    rep.add_argument("--context", type=int, default=3, help="diff context lines (default 3)")
    rep.add_argument("--max-diff-lines", type=int, default=2000,
                     help="max diff lines rendered per policy in HTML (full diff always saved)")

    ap = argparse.ArgumentParser(description="Export and diff BIG-IP ASM policies across an upgrade.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("export", parents=[common, rep], help="snapshot ASM policies from device(s)")
    ex.add_argument("--phase", required=True, choices=["pre", "post"])
    tgt = ex.add_argument_group("targets (at least one)")
    tgt.add_argument("--host", action="append", help="BIG-IP IP or hostname (repeatable)")
    tgt.add_argument("--hosts-file", help="file with one BIG-IP IP/hostname per line")
    ex.add_argument("-u", "--username", required=True)
    ex.add_argument("-p", "--password", help="password (else $BIGIP_PASSWORD, else prompt)")
    ex.add_argument("--login-provider", default="tmos", help="loginProviderName (default tmos)")
    ex.add_argument("--format", choices=["xml", "json"], default="xml",
                    help="export format; json needs a BIG-IP version that supports JSON export")
    ex.add_argument("--verify", action="store_true", help="verify TLS certificates")
    ex.add_argument("--ca-bundle", help="CA bundle for TLS verification (implies --verify)")
    ex.add_argument("--timeout", type=int, default=60, help="HTTP timeout seconds (default 60)")
    ex.add_argument("--task-timeout", type=int, default=600,
                    help="max seconds to wait for each export task (default 600)")
    ex.add_argument("--workers", type=int, default=4, help="devices processed in parallel (default 4)")
    ex.add_argument("--force", action="store_true", help="overwrite an existing snapshot for this phase")
    ex.add_argument("--no-report", action="store_true", help="skip auto report after --phase post")

    sub.add_parser("report", parents=[common, rep], help="build the HTML diff report from snapshots")

    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    if args.cmd == "export":
        args.verify_arg = args.ca_bundle or bool(args.verify)
        if not args.verify_arg:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return cmd_export(args)
    return cmd_report(args)


if __name__ == "__main__":
    sys.exit(main())
