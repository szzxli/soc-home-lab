# GoPhish Self-Test Guide: Phish Yourself (Safely and Legally)

> ## ⚠️ COMPLIANCE BOX — READ FIRST
> **ONLY target your own mailbox.** This guide is for sending simulated phishing emails to **email addresses you personally own and control**.
> Sending phishing simulations to anyone else — coworkers, friends, strangers — without their **prior written authorization** may violate anti-phishing and computer-crime laws (e.g. the Computer Fraud and Abuse Act in the US, and equivalent statutes elsewhere) and can get you fired, sued, or prosecuted. "It was just a test" is not a defense.
> - Self-authorization is sufficient **only** because the sole recipient is you.
> - If you ever want to test anyone else, get explicit written permission first, keep the scope in writing, and follow your organization's approved phishing-simulation policy.
> - Never use real credential-harvesting pages against real people. In this lab, the "landing page" only records that *you* clicked — it captures nothing sensitive.

**Why do this?** Reading about phishing analysis is passive. Sending a simulated phish to yourself, then analyzing it with the walkthrough method from this project, closes the loop: you see what a phish looks like from the *analyst's* chair when you already know the answer, which trains your eye for the ones where you don't.

---

## Prerequisites

- A machine you control (Linux/macOS/Windows with WSL) — this lab uses GoPhish, a legitimate open-source phishing-simulation framework.
- An email address you own (e.g. a personal Gmail) that you will use as the **only** target.
- A sending method. Two honest options:
  - **Option A (recommended for beginners):** your email provider's SMTP with an app password. Delivery is realistic and setup is simple.
  - **Option B:** a local mail relay. More setup, more control over headers.
- Do **not** use a corporate mail system or anyone else's infrastructure for this.

---

## Step 1 — Install GoPhish

```bash
# Download the latest release for your platform from:
# https://github.com/gophish/gophish/releases
# Then:
unzip gophish-v*.zip -d gophish && cd gophish
chmod +x gophish
./gophish
```

- Admin UI: `https://localhost:3333` (default credentials `admin` / `gophish` — **change these immediately**).
- Phishing server (landing pages): `http://localhost:80`.

> Security note: GoPhish is dual-use software — it is the same tool real attackers misuse. Running it against your own mailbox for defensive training is legitimate; pointing it at anyone else without authorization is not. Keep the admin panel bound to localhost and shut GoPhish down when you're done.

## Step 2 — Configure a Sending Profile (your own mailbox only)

1. In the GoPhish admin UI, go to **Sending Profiles → New Profile**.
2. Fill in *your* SMTP details (e.g. your personal Gmail SMTP + app password).
3. Set the **From address** to an address you own. Do **not** spoof a real company's domain — use a clearly fake training domain you control or your own address with a suspicious display name (e.g. `"IT Helpdesk" <you@yourdomain>`), so the simulation is realistic but not impersonating anyone real.
4. Send a test email to yourself and confirm delivery before building the campaign.

## Step 3 — Build the Campaign (target: you, and only you)

1. **Email Template:** write a lure modeled on the reconstructed sample in `sample-walkthrough.md` — e.g. "password expires in 24 hours" with a link to your GoPhish landing page. Include at least one obfuscation technique from the cheatsheet (subdomain trick or an encoded URL) so you have something real to decode later.
2. **Landing Page:** use GoPhish's built-in template or a simple clone that **only logs the click/submit event** — do not build a page that harvests real passwords, even your own.
3. **Users & Groups:** create a group containing **only your own email address**. Double-check the recipient list: one address, yours.
4. **Launch** the campaign to that single-recipient group.

## Step 4 — Analyze Your Own Phish (the actual lab exercise)

Once the email lands in your inbox:

1. **Do not click the link yet.** First, pull the full headers (in Gmail: *Show original*).
2. Work through **`sample-walkthrough.md`** as your procedure checklist:
   - Header analysis: trace the `Received` chain bottom-up; compare `Return-Path` / `From` / `Reply-To`.
   - Read the `Authentication-Results`: what do SPF/DKIM/DMARC say about *your* simulated send? (Expect: SPF may pass if you used your own SMTP — note how a *passing* SPF does not make the mail legitimate, since the `From` identity is still fake. That's the lesson.)
   - URL analysis: decode your obfuscated link layer by layer (`urllib.parse.unquote`, `base64.b64decode`, `curl -I` on the landing page).
   - Write your verdict and severity rating *before* looking at the next step.
3. **Then** click through and compare: did GoPhish record the click? Did your analysis predict the landing behavior? Fill in **`report-template.md`** with your findings.

## Step 5 — Self-Check

Score yourself honestly:

- [ ] I identified the `Return-Path` / `From` / `Reply-To` relationship correctly.
- [ ] I correctly interpreted every line of the `Authentication-Results` header.
- [ ] I decoded the URL to its final destination without clicking it first.
- [ ] I can explain why SPF passing did not make the email safe (envelope ≠ header identity).
- [ ] I wrote a verdict with severity, confidence, and at least one piece of exculpatory-evidence consideration.
- [ ] I completed a full report using `report-template.md` with no fabricated fields.
- [ ] The campaign targeted only my own address, and GoPhish is shut down.

**Stretch goal:** run the exercise twice with different lures (e.g. a fake "shared document" notification, then a fake shipping notification). Compare which obfuscation technique was hardest for *you-as-analyst* to unwind — that's the technique to study next.

---

## Cleanup

- Delete the campaign data from GoPhish when finished (it contains your own address — treat it as personal data).
- Revoke the SMTP app password you created for the test.
- Keep your completed `report-template.md` as a portfolio artifact (redact your personal email address first).

---

*Repository: https://github.com/szzxli/soc-home-lab — project `03-phishing-analysis-lab`.*
