# Hunt checklist — M365 app-identity persistence (ConnectWise Cloud Backup incident pattern, Oct 2026)

Work top to bottom. Check the box when done, note what you found.
Companion: `../../soc-skills/labs/m365-app-identity-persistence.md`

## 0. Incident reality check (facts as of 2026-10-20)
- [ ] On **2026-10-15** ConnectWise found unauthorized access to
      application identities in its **Cloud Backup** (formerly
      SkyKick) environment. **Cloud Backup, SaaS Security, and Cloud
      Management are suspended** while it investigates.
- [ ] Huntress confirmed a Cloud Backup **M365 API secret was stolen**
      and used to access customer tenants. In one tenant, the app
      **ConnectWise Cloud Management - MS Teams** (App ID
      `24205314-2b89-4e07-a2a4-579e898a5640`) **gave itself Global
      Administrator** and **added credentials to two other apps**.
- [ ] There is **no CVE and no patch**. The fix is an audit: review
      the credentials on **every** application in the tenant.
      Disabling the vendor's apps does **not** remove credentials
      that were already added elsewhere.

## 1. Am I even in scope?
- [ ] Does any third-party SaaS product hold an application identity
      (service principal + secret/certificate) in your tenant —
      backup, security tooling, management agents, sync tools?
      Inventory them; an app identity you can't name an owner for
      is already a finding.
- [ ] Which of those applications hold privileged directory roles or
      broad Graph permissions? That list is your blast radius.
- [ ] Does your tenant retain Entra ID audit records for role
      changes, application credential changes, and service-principal
      sign-ins — for ≥90 days? If not, write down the gap; this hunt
      depends on those records existing.

## 2. The persistence signature (M365 / Entra ID audit log)
- [ ] **Service principal granted a privileged role** — Global
      Administrator first, then Privileged Role Administrator,
      Privileged Authentication Administrator, Application /
      Cloud Application Administrator, Exchange / SharePoint /
      Security / User Administrator.
- [ ] **New credentials on a service principal** — a certificate or
      secret added to any application, above all to applications
      *other* than the one the vendor is having an incident with.
- [ ] **The change was made BY an application** — role assignments
      and credential adds whose initiator is a service principal,
      not a human admin.
- [ ] **Burst across applications** — one actor touching ≥3 distinct
      applications (roles or credentials) within 30 minutes.
- [ ] **Service-principal sign-in from a new IP** — the application
      authenticating from outside its known egress (vendor
      datacenters, your NAT ranges).

## 3. Separate routine administration from the pattern firing
- [ ] Credential rotation by your change-controlled admins, from
      their known IPs, is routine — that (IP, admin) pair belongs on
      the allowlist, with a ticket behind each rotation.
- [ ] A credential add by a human who is **not** on that path is not
      automatically an attack — but it lands at SUSPICIOUS until a
      change record explains it. Fix the process so rotations happen
      on the allowlisted path.
- [ ] A **non-privileged** role grant (e.g. Directory Readers) to a
      service principal by a human is normal app onboarding — no
      marker, unless the actor is an application or it arrives
      inside a burst.

## 4. Containment (the order matters)
- [ ] **Census before cleanup:** export every application's
      credential list (certificates + secrets, with creation dates)
      and every privileged role assignment **before** removing
      anything — the census is both your eradication list and your
      evidence.
- [ ] Remove every credential you cannot attribute to a named human
      and a change record, on **all** applications — not just the
      vendor's. Then rotate the credentials you keep.
- [ ] Strip privileged roles from service principals that cannot
      justify them in writing; re-grant narrowly if the vendor
      genuinely requires one.
- [ ] Only **then** disable or remove the abused applications.
      Doing this step first is the documented trap: it feels like
      containment and removes nothing the attacker added.

## 5. Blast radius
- [ ] Treat any confirmed app-actor role grant or credential add as
      tenant-level compromise: the actor held (or minted) keys with
      tenant-wide reach, so review data-plane activity for every
      application it touched — mail/file access by those app
      identities for the whole exposure window.
- [ ] Check for follow-on persistence outside applications: new
      admin users, changed conditional-access / federation settings,
      new enterprise-app consents — an actor with Global Admin
      rarely stops at credentials.
- [ ] Preserve the audit-log export before retention eats it; the
      timeline in §2 is your incident record.

## Correlation
- [ ] Privileged role granted to a service principal → incident;
      run the full credential census before any cleanup
- [ ] Credentials added to an app, performed BY an app → incident
      (persistence being planted — census first, then remove)
- [ ] App performing admin changes / cross-app burst / sign-in from
      a new IP, alone → suspicious; escalate immediately if the
      vendor is mid-incident
- [ ] Credential add by an unlisted human → suspicious; match it to
      a change record or treat it as unattributed and remove it
