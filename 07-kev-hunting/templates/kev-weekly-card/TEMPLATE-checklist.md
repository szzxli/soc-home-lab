# KEV weekly card — TEMPLATE

Copy this folder for each new week, then replace every `[PLACEHOLDER]`.
Do not publish a card with placeholders still in it. All log lines and
indicators in this template are synthetic: source addresses use only the
documentation ranges in RFC 5737 (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and hostnames use only example.com / example.org.
A detection match means the log contains the pattern; it does not by itself
prove compromise — triage every match before concluding anything.

## Week of [YYYY-MM-DD]

| CVE | Vendor / product | KEV added | Federal due | Status |
| --- | ---------------- | --------- | ----------- | ------ |
| [CVE-YYYY-NNNNN] | [Vendor Product] | [YYYY-MM-DD] | [YYYY-MM-DD] | in CISA KEV |

## 1. Confirm the listing

- [ ] Check the CVE against the official CISA KEV feed and NVD; record the
      exact vendor, product, vulnerability name, date added, and due date.
- [ ] Add the CVE to `07-kev-hunting/kev-manifest.json` with its KEV dates.
- [ ] Run `python3 tools/verify_kev.py` — it must report all claims match
      before the card is published.

## 2. Hunt checklist

- [ ] Identify which log source shows the attack (web access log, Sysmon,
      appliance log, or other) and pull that window.
- [ ] Hunt the signature: [describe the request / event pattern here].
- [ ] Cluster by (source address, path): bursts of failures followed by a
      success on a sensitive path = the pattern to confirm.
- [ ] Check the same addresses against firewall / IDS logs for the same
      window — look for what came after the first hit.
- [ ] Scope: which of your systems run the affected product and are
      internet-facing? Cloud instances may already be patched — verify,
      do not assume.

## 3. Synthetic log + detection

- [ ] `TEMPLATE-sample.log` shows the pattern with benign traffic mixed in.
- [ ] `TEMPLATE-detection.yml` is the Sigma rule for the pattern; tune the
      field names to your log source before use.
- [ ] Write your own detection first, then compare with the reference.

## 4. Sources and verification

- **Sources:** [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [NVD](https://nvd.nist.gov/vuln/detail/[CVE-YYYY-NNNNN])
- After publishing, the weekly job re-checks KEV status; when it changes,
  run `python3 tools/verify_kev.py --write --stamp` locally and open a PR.
  Never hand-edit a `kev-verify` block — regenerate it with the script.
