"""GoatCounter test-visit guard: every page loads count.js only through the guard, and the guard
skips ?nocount=1 (sticky via localStorage 'skipgc'), v=, cb=, cachebust, _= and nocount URLs.
The logic check runs the page's own inline guard in node (skipped when node is missing)."""
import json, re, shutil, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGES = ["web/index.html", "web/demo.html", "_includes/head-custom.html"]
ANALYTICS = ["web/js/analytics.js"]
STATIC = re.compile(r'<script[^>]*data-goatcounter=[^>]*src="https://gc\.zgo\.at/count\.js"')
GUARD = re.compile(r"<script>/\* GoatCounter loader:.*?</script>", re.S)


def _guard(page):
    m = GUARD.findall((ROOT / page).read_text(encoding="utf-8"))
    assert len(m) == 1, f"{page}: exactly one GoatCounter loader"
    return m[0]


def test_every_page_uses_the_guarded_loader():
    first = _guard(PAGES[0])
    for page in PAGES:
        html = (ROOT / page).read_text(encoding="utf-8")
        assert not STATIC.search(html), f"{page}: static count.js tag would bypass the guard"
        g = _guard(page)
        assert g == first, f"{page}: loader differs from {PAGES[0]}"
        assert "https://szzxli.goatcounter.com/count" in g and "skipgc" in g


def test_event_senders_respect_the_guard():
    for f in ANALYTICS:
        assert "if (window.gcSkip) return;" in (ROOT / f).read_text(encoding="utf-8"), f


CASES = [  # (url query, stored flag before, expect counted, flag after)
    ("", None, True, None), ("?ref=gh-x", None, True, None), ("?nav=1", None, True, None),
    ("?nocount=1", None, False, "t"), ("?ref=x&nocount=1", None, False, "t"), ("", "t", False, "t"),
    ("?nocount=0", "t", False, None), ("?v=20261029", None, False, None), ("?cb=3", None, False, None),
    ("?cachebust", None, False, None), ("?cachebust=1", None, False, None), ("?a=1&_=123", None, False, None),
]


def test_guard_logic_in_node():
    node = shutil.which("node")
    if not node:
        import pytest; pytest.skip("node not installed")
    js = _guard(PAGES[0])[len("<script>"):-len("</script>")]
    runner = """
const cases = %s; const out = [];
for (const [q, flag] of cases) {
  const store = {}; if (flag) store.skipgc = flag;
  const added = [];
  const w = {localStorage: {getItem: k => k in store ? store[k] : null, setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; }}};
  const el = {setAttribute(k, v) { this[k] = v; }};
  const d = {createElement: () => el, head: {appendChild: e => added.push(e)}};
  (function (window, document, location) { %s })(w, d, {search: q});
  out.push([added.length === 1 && added[0]['data-goatcounter'] === 'https://szzxli.goatcounter.com/count', store.skipgc || null, w.gcSkip]);
}
console.log(JSON.stringify(out));
""" % (json.dumps([[c[0], c[1]] for c in CASES]), js)
    res = json.loads(subprocess.run([node, "-e", runner], capture_output=True, text=True, check=True).stdout)
    for (q, flag, counted, after), (loaded, stored, skip) in zip(CASES, res):
        assert loaded == counted and skip == (not counted), (q, flag)
        assert stored == after, (q, flag, stored)
