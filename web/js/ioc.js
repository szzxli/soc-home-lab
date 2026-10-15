/* IOC Analyzer — JS port of 02-python-ioc-analyzer/ioc_analyzer.py
 * Faithful port of the three heuristic detectors:
 *   unusual_geo  — successful ConsoleLogin from IP outside the demo
 *                  common-range table (demo heuristic, not real GeoIP)
 *   brute_force  — >=5 failed ConsoleLogins from one IP within 10 minutes
 *   suspicious_api — IAM policy mutations & other high-risk API calls
 * AbuseIPDB enrichment is intentionally unavailable in the browser build;
 * the report states that, exactly like the CLI does without an API key.
 */
"use strict";

/* ---- Detection configuration (identical to ioc_analyzer.py) ---- */
const COMMON_IP_NETWORKS = [
  "3.0.0.0/8",      // AWS US-East
  "13.52.0.0/16",   // Example US corporate egress (fictional)
  "44.192.0.0/10",  // AWS US-East public range
  "52.0.0.0/8",     // AWS US-East public range
  "54.0.0.0/8",     // AWS US-East public range
  "72.14.0.0/16"    // Example US corporate egress (fictional)
];

const SUSPICIOUS_API_CALLS = {
  "PutUserPolicy":   ["high",   "Inline IAM policy attached directly to a user — common persistence technique."],
  "AttachUserPolicy":["high",   "Managed IAM policy attached to a user — possible privilege escalation."],
  "AttachRolePolicy":["high",   "Managed IAM policy attached to a role — possible privilege escalation."],
  "CreateAccessKey": ["medium", "New IAM access key created — check whether it was authorized."],
  "DeleteTrail":     ["high",   "CloudTrail logging disabled — classic defense-evasion indicator."],
  "StopLogging":     ["high",   "CloudTrail logging stopped — classic defense-evasion indicator."],
  "RunInstances":    ["medium", "EC2 instances launched — investigate for cryptojacking / resource abuse."]
};

/* ---- Parsing ---- */
function iocParseRecords(data) {
  let records;
  if (data && typeof data === "object" && !Array.isArray(data)) {
    records = data.Records || [];
  } else if (Array.isArray(data)) {
    records = data; // tolerate a bare array of records
  } else {
    records = [];
  }
  return records.filter(r => r && typeof r === "object");
}

function iocParseTime(value) {
  if (!value) return null;
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

/* Python datetime.isoformat() on an aware UTC datetime renders
 * "2026-10-10T12:01:03+00:00" — match that format for parity. */
function iocIso(dt) {
  return dt.toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

function iocSourceIp(record) { return record.sourceIPAddress || null; }

function iocActor(record) {
  const ui = record.userIdentity || {};
  for (const key of ["userName", "principalId", "arn"]) {
    if (ui[key]) return String(ui[key]);
  }
  return "unknown";
}

function iocEventName(record) { return String(record.eventName || "unknown"); }

function iocIsConsoleLogin(record) { return iocEventName(record) === "ConsoleLogin"; }

function iocLoginSucceeded(record) {
  const resp = record.responseElements;
  if (resp && typeof resp === "object") {
    const status = resp.ConsoleLogin;
    if (status === "Success" || status === "Failure") return status === "Success";
  }
  // Fall back to errorCode: its presence means the call failed.
  return !("errorCode" in record);
}

/* ---- CIDR matching (mirrors ipaddress.ip_address / ip_network) ---- */
function iocIpToInt(ip) {
  if (typeof ip !== "string") return null;
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    if (!/^\d+$/.test(part)) return null;
    const v = parseInt(part, 10);
    if (v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n >>> 0;
}

function iocInCidr(ip, cidr) {
  const parts = String(cidr).split("/");
  if (parts.length !== 2) return false;
  const addr = iocIpToInt(ip);
  const net = iocIpToInt(parts[0]);
  const bits = parseInt(parts[1], 10);
  if (addr === null || net === null || isNaN(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
  return ((addr & mask) >>> 0) === ((net & mask) >>> 0);
}

function iocIpInCommonRanges(ip, networks) {
  if (iocIpToInt(ip) === null) return false; // mirrors Python: invalid IP -> not "common" -> flagged? no:
  // NOTE: Python _ip_in_common_ranges returns False on ValueError, and the
  // geo detector then flags the login (ip present but not in ranges).
  // Keep identical semantics here.
  for (const net of networks || COMMON_IP_NETWORKS) {
    if (iocInCidr(ip, net)) return true;
  }
  return false;
}

/* ---- Detectors ---- */
function iocDetectUnusualGeo(records, networks) {
  const findings = [];
  for (const record of records) {
    if (!iocIsConsoleLogin(record) || !iocLoginSucceeded(record)) continue;
    const ip = iocSourceIp(record);
    if (!ip || iocIpInCommonRanges(ip, networks)) continue;
    findings.push({
      detector: "unusual_geo",
      time: record.eventTime || "unknown",
      event: iocEventName(record),
      actor: iocActor(record),
      ip: ip,
      risk: "medium",
      evidence: "Successful ConsoleLogin from an IP outside the built-in common-range table (demo heuristic; verify with GeoIP)."
    });
  }
  return findings;
}

function iocDetectBruteForce(records, windowMinutes, threshold) {
  windowMinutes = windowMinutes == null ? 10 : windowMinutes;
  threshold = threshold == null ? 5 : threshold;
  const byIp = {};
  for (const record of records) {
    if (!iocIsConsoleLogin(record) || iocLoginSucceeded(record)) continue;
    const ip = iocSourceIp(record);
    const ts = iocParseTime(record.eventTime);
    if (!ip || ts === null) continue;
    (byIp[ip] = byIp[ip] || []).push([ts, record]);
  }
  const windowMs = windowMinutes * 60 * 1000;
  const findings = [];
  for (const ip of Object.keys(byIp)) {
    const events = byIp[ip].sort((a, b) => a[0] - b[0]);
    for (let i = 0; i < events.length; i++) {
      let j = i;
      while (j < events.length && events[j][0] - events[i][0] <= windowMs) j++;
      const count = j - i;
      if (count >= threshold) {
        const firstTs = iocIso(events[i][0]);
        const lastTs = iocIso(events[j - 1][0]);
        findings.push({
          detector: "brute_force",
          time: firstTs,
          event: "ConsoleLogin (failed)",
          actor: iocActor(events[i][1]),
          ip: ip,
          risk: "high",
          evidence: count + " failed ConsoleLogin attempts from " + ip +
            " within " + windowMinutes + " minutes (" +
            firstTs + " → " + lastTs + "; threshold " + threshold + ")."
        });
        break; // one finding per IP
      }
    }
  }
  return findings;
}

function iocDetectSuspiciousApi(records, watchlist) {
  watchlist = watchlist || SUSPICIOUS_API_CALLS;
  const findings = [];
  for (const record of records) {
    const name = iocEventName(record);
    if (!(name in watchlist)) continue;
    const [risk, rationale] = watchlist[name];
    const params = record.requestParameters || {};
    findings.push({
      detector: "suspicious_api",
      time: record.eventTime || "unknown",
      event: name,
      actor: iocActor(record),
      ip: iocSourceIp(record) || "n/a",
      risk: risk,
      evidence: rationale + " Request parameters: " + JSON.stringify(params)
    });
  }
  return findings;
}

function iocDetectAll(records, bruteForceWindow, bruteForceThreshold) {
  let findings = [];
  findings = findings.concat(iocDetectUnusualGeo(records));
  findings = findings.concat(iocDetectBruteForce(records, bruteForceWindow, bruteForceThreshold));
  findings = findings.concat(iocDetectSuspiciousApi(records));
  findings.sort((a, b) => String(a.time) < String(b.time) ? -1 : String(a.time) > String(b.time) ? 1 : 0);
  return findings;
}

function iocBuildSummary(records, findings) {
  const events = {}, ips = new Set(), actors = new Set(), times = [];
  for (const r of records) {
    const e = iocEventName(r);
    events[e] = (events[e] || 0) + 1;
    const ip = iocSourceIp(r);
    if (ip) ips.add(ip);
    actors.add(iocActor(r));
    const ts = iocParseTime(r.eventTime);
    if (ts) times.push(ts);
  }
  const riskCounts = {};
  for (const f of findings) riskCounts[f.risk] = (riskCounts[f.risk] || 0) + 1;
  const topEvents = Object.keys(events).map(k => [k, events[k]])
    .sort((a, b) => b[1] - a[1]).slice(0, 10);
  return {
    total_records: records.length,
    time_range: times.length
      ? iocIso(new Date(Math.min.apply(null, times))) + " → " + iocIso(new Date(Math.max.apply(null, times)))
      : "n/a",
    unique_source_ips: ips.size,
    unique_actors: actors.size,
    top_events: topEvents,
    total_findings: findings.length,
    findings_by_risk: riskCounts
  };
}

/* Export for node cross-validation; harmless in browsers. */
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    COMMON_IP_NETWORKS, SUSPICIOUS_API_CALLS,
    iocParseRecords, iocParseTime, iocIso,
    iocDetectUnusualGeo, iocDetectBruteForce, iocDetectSuspiciousApi,
    iocDetectAll, iocBuildSummary
  };
}
