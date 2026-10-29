# Contributing / testing the site

## Test without counting (humans and agents)

Open the site with `?nocount=1` once, e.g. <https://szzxli.github.io/soc-home-lab/web/?nocount=1>.
That browser then counts nothing in GoatCounter (page views and events) until you open any page with `?nocount=0`.
It sets GoatCounter's own `skipgc` flag in localStorage, the same one `#toggle-goatcounter` sets.

- Automated / headless browsers start with a fresh profile: add `?nocount=1` to **every** URL you open.
- URLs containing `v=`, `cb=`, `cachebust`, `_=` or `nocount` are never counted, so cache-busting test URLs stay out of the stats.
- Local copies (`localhost`, `file://`) are never counted.

The loader is the inline `GoatCounter loader` script in each page; `web/tests/test_goatcounter_guard.py` checks it.

## Links to the other sites

Links from this repo to li jun's other sites carry a `?ref=` source tag (placed before any `#fragment`):
`?ref=gh-shl` from Markdown files in this repo, `?ref=shl` from the website. Links to third-party sites are not tagged.
