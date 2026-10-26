"""Basic smoke checks for the static site in web/.

Guards the things the redesign must keep: the main CTAs, the GoatCounter /
analytics.js event hooks (open-lab/*, run-demo/*), SEO/OG meta, alt text, and
that every local link or asset resolves to a real file. Stdlib only.
Run: python -m pytest web/tests -q
"""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest

WEB = Path(__file__).resolve().parent.parent
REPO = "https://github.com/szzxli/soc-home-lab"
LABS = ["01-mini-soc", "02-python-ioc-analyzer", "03-phishing-analysis-lab", "04-rea-triage",
        "05-soc-skills", "06-ghostaction-supply-chain", "07-kev-hunting"]


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def find(self, tag):
        return [a for t, a in self.tags if t == tag]

    def hrefs(self):
        return [a.get("href", "") for t, a in self.tags if t == "a"]


def load(name):
    return Page((WEB / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def index():
    return load("index.html")


@pytest.fixture(scope="module")
def demo():
    return load("demo.html")


def test_primary_cta_goes_to_demo(index):
    prim = [a for t, a in index.tags if t == "a" and "btn-primary" in (a.get("class") or "").split()]
    assert len(prim) == 1, "exactly one primary CTA"
    assert prim[0]["href"] == "demo.html"


def test_main_functions_reachable_from_homepage(index):
    h = index.hrefs()
    assert "demo.html" in h                                   # run the demo
    assert "#kev" in h and any(a.get("id") == "kev" for _, a in index.tags)  # browse KEV labs
    assert f"{REPO}/blob/main/START_HERE.md" in h               # start here
    assert REPO in h                                           # repo
    for lab in LABS:                                           # open every lab
        assert any(x.endswith("/" + lab) for x in h), lab


def test_collapsible_sections_exist(index, demo):
    assert len(index.find("details")) >= 5
    assert len(demo.find("details")) >= 1


def test_analytics_loaded_on_every_page(index, demo):
    for p in (index, demo):
        assert any(a.get("src") == "js/analytics.js" for t, a in p.tags if t == "script")


def test_analytics_hooks_intact():
    js = (WEB / "js" / "analytics.js").read_text(encoding="utf-8")
    assert "GOATCOUNTER_CODE = 'szzxli-sec'" in js
    for needle in ("'open-lab/'", "open-lab/live-demo", "open-lab/repo", "run-demo/sample",
                   "run-demo/pasted", "runSample", "runCustom", "customJson", "data-count"):
        assert needle in js, needle


def test_demo_controls_match_analytics_ids(demo):
    for id_ in ("runSample", "runCustom", "customJson", "report"):
        assert any(a.get("id") == id_ for _, a in demo.tags), id_


@pytest.mark.parametrize("name", ["index.html", "demo.html"])
def test_seo_and_og_meta(name):
    p = load(name)
    props = {a.get("property") for t, a in p.tags if t == "meta"}
    names = {a.get("name") for t, a in p.tags if t == "meta"}
    assert {"og:title", "og:description", "og:url", "og:image", "og:type"} <= props
    assert {"description", "viewport", "twitter:card", "twitter:title", "twitter:image"} <= names
    assert any(a.get("rel") == "canonical" for t, a in p.tags if t == "link")
    assert any(t == "html" and a.get("lang") == "en" for t, a in p.tags)


def test_jsonld_present(index):
    assert any(a.get("type") == "application/ld+json" for t, a in index.tags if t == "script")


@pytest.mark.parametrize("name", ["index.html", "demo.html"])
def test_images_have_alt_and_local_refs_resolve(name):
    p = load(name)
    for t, a in p.tags:
        if t == "img":
            assert (a.get("alt") or "").strip(), "img needs alt text"
        ref = a.get("href") if t in ("a", "link") else a.get("src") if t in ("img", "script") else None
        if not ref or ref.startswith("#") or urlparse(ref).scheme:
            continue
        path = ref.split("#")[0].split("?")[0] or "index.html"
        target = WEB / path
        if target.is_dir():
            target = target / "index.html"
        assert target.exists(), f"{name}: broken local ref {ref}"


# --- credibility pass (2026-10): honesty note, differentiators, go deeper, KEV tiles, noisy demo ---

def _text(name):
    return (WEB / name).read_text(encoding="utf-8")


def test_what_this_is_isnt_note_is_collapsed_in_hero():
    html = _text("index.html")
    hero = html[html.index('<div class="hero">'):html.index('<section id="labs"')]
    assert '<details class="isnt" id="what-this-is">' in hero and "<details class=\"isnt\" id=\"what-this-is\" open" not in hero
    for phrase in ("beginner-to-intermediate", "synthetic", "isn't</b> proof of job readiness", "real SOC volume"):
        assert phrase in hero, phrase


def test_differentiators_visible_in_hero():
    html = _text("index.html")
    hero = html[html.index('<div class="hero">'):html.index('<section id="labs"')]
    assert "re-verified weekly" in hero and "CISA" in hero
    assert "Runs in your browser" in hero
    assert 'href="https://szzxli.github.io/soc-skills/web/"' in hero and "gap analysis" in hero


GO_DEEPER = ["https://github.com/redcanaryco/atomic-red-team", "https://bots.splunk.com/",
             "https://cyberdefenders.org/blueteam-ctf-challenges/", "https://letsdefend.io/",
             "https://blueteamlabs.online/"]


def test_go_deeper_collapsible_links(index):
    html = _text("index.html")
    block = html[html.index('<details id="go-deeper">'):]
    block = block[:block.index("</details>")]
    for url in GO_DEEPER:
        assert f'href="{url}"' in block, url
    for name in ("Atomic Red Team", "Splunk", "CyberDefenders", "LetsDefend", "Blue Team Labs Online"):
        assert name in block


def test_every_kev_tile_declares_its_kev_status(index):
    tiles = [a for t, a in index.tags if t == "article" and "data-kev" in a]
    assert len(tiles) == 10
    assert sum(a["data-kev"] == "yes" for a in tiles) == 6
    html = _text("index.html")
    assert "PRA" not in html  # KEV, NVD and BT26-05 name Remote Support only


def test_demo_noisy_sample_button_and_files():
    demo = _text("demo.html")
    assert 'id="runNoisy"' in demo and "iocScore" in demo
    for rel in ("../02-python-ioc-analyzer/sample_data/sample_cloudtrail_noisy.json",
                "../02-python-ioc-analyzer/sample_data/sample_cloudtrail_noisy.truth.json"):
        assert f'"{rel}"' in demo and (WEB / rel).resolve().exists(), rel
    assert "run-demo/noisy" in _text("js/analytics.js")
