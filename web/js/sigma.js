(function () {
  'use strict';

  function lookupField(record, field) {
    var cur = record;
    var parts = String(field || '').split('.');
    for (var i = 0; i < parts.length; i++) {
      if (cur && typeof cur === 'object' && Object.prototype.hasOwnProperty.call(cur, parts[i])) {
        cur = cur[parts[i]];
      } else {
        return { found: false, value: undefined };
      }
    }
    return { found: true, value: cur };
  }

  function matchValue(expected, actual, modifier) {
    if (actual === undefined || actual === null) return false;
    var a = String(actual).toLowerCase();
    var e = String(expected).toLowerCase();
    if (modifier === 'contains') return a.indexOf(e) !== -1;
    if (modifier === 'startswith') return a.indexOf(e) === 0;
    if (modifier === 'endswith') return a.slice(-e.length) === e;
    return a === e;
  }

  function matchItem(item, record) {
    var got = lookupField(record, item.field);
    if (!got.found) return false;
    var values = item.values || [];
    for (var i = 0; i < values.length; i++) {
      if (matchValue(values[i], got.value, item.modifier || '')) return true;
    }
    return false;
  }

  function matchSelection(items, record) {
    if (!items || !items.length) return false;
    for (var i = 0; i < items.length; i++) {
      if (!matchItem(items[i], record)) return false;
    }
    return true;
  }

  function tokenize(condition) {
    var tokens = [];
    var i = 0;
    var s = String(condition || '');
    while (i < s.length) {
      var ch = s[i];
      if (/\s/.test(ch)) { i++; continue; }
      if (ch === '(' || ch === ')') { tokens.push(ch); i++; continue; }
      var j = i;
      while (j < s.length && !/\s/.test(s[j]) && s[j] !== '(' && s[j] !== ')') j++;
      tokens.push(s.slice(i, j));
      i = j;
    }
    return tokens;
  }

  function evalCondition(condition, results) {
    var tokens = tokenize(condition);
    var pos = 0;
    function peek() { return pos < tokens.length ? tokens[pos] : null; }
    function next() { return tokens[pos++]; }
    function expand(pattern) {
      if (pattern === 'them') return Object.keys(results);
      if (pattern.slice(-1) === '*') {
        var prefix = pattern.slice(0, -1);
        return Object.keys(results).filter(function (n) { return n.indexOf(prefix) === 0; });
      }
      return Object.prototype.hasOwnProperty.call(results, pattern) ? [pattern] : [];
    }
    function parsePrimary() {
      var t = next();
      if (t === '(') {
        var v = parseOr();
        if (next() !== ')') throw new Error('unbalanced condition');
        return v;
      }
      if (t === '1' || t === 'all') {
        if (next() !== 'of') throw new Error('bad of condition');
        var names = expand(next());
        if (!names.length) return false;
        if (t === '1') return names.some(function (n) { return !!results[n]; });
        return names.every(function (n) { return !!results[n]; });
      }
      if (!Object.prototype.hasOwnProperty.call(results, t)) throw new Error('unknown selection ' + t);
      return !!results[t];
    }
    function parseNot() {
      if (peek() === 'not') { next(); return !parseNot(); }
      return parsePrimary();
    }
    function parseAnd() {
      var v = parseNot();
      while (peek() === 'and') { next(); var r = parseNot(); v = v && r; }
      return v;
    }
    function parseOr() {
      var v = parseAnd();
      while (peek() === 'or') { next(); var r = parseAnd(); v = v || r; }
      return v;
    }
    var out = parseOr();
    if (pos !== tokens.length) throw new Error('trailing condition tokens');
    return out;
  }

  function matchRule(rule, record) {
    var results = {};
    var names = Object.keys(rule.detection || {});
    for (var i = 0; i < names.length; i++) {
      results[names[i]] = matchSelection(rule.detection[names[i]], record);
    }
    if (!rule.condition) return names.length === 1 ? !!results[names[0]] : false;
    return evalCondition(rule.condition, results);
  }

  function actorOf(record) {
    var got = lookupField(record, 'userIdentity.userName');
    if (got.found && got.value) return String(got.value);
    if (record && record.userName) return String(record.userName);
    return 'unknown';
  }

  function scanRecords(records, rules) {
    var findings = [];
    (records || []).forEach(function (record, idx) {
      (rules || []).forEach(function (rule) {
        if (matchRule(rule, record)) {
          findings.push({
            ruleId: rule.id,
            ruleTitle: rule.title,
            level: rule.level,
            recordIndex: idx,
            actor: actorOf(record),
            time: record.eventTime || record.timestamp || '',
            event: record.eventName || record.event_type || ''
          });
        }
      });
    });
    return findings;
  }

  function parseRecords(text) {
    var parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed;
    if (parsed && Array.isArray(parsed.Records)) return parsed.Records;
    if (parsed && typeof parsed === 'object') return [parsed];
    throw new Error('JSON must be an array, an object with Records, or one record object.');
  }

  function buildShareUrl(base, sampleId, ruleIds) {
    var u = new URL(base);
    u.search = '';
    u.hash = '';
    u.searchParams.set('ref', 'sigma-play');
    u.searchParams.set('sample', sampleId);
    u.searchParams.set('rules', (ruleIds || []).join(','));
    return u.toString();
  }

  function parseShareParams(search, data) {
    var q = new URLSearchParams(search || '');
    var sampleId = q.get('sample') || '';
    var sampleOk = (data.samples || []).some(function (s) { return s.id === sampleId; });
    var valid = {};
    (data.rules || []).forEach(function (r) { valid[r.id] = true; });
    var ruleIds = (q.get('rules') || '').split(',').map(function (s) { return s.trim(); }).filter(function (id) { return !!valid[id]; });
    return { sampleId: sampleOk ? sampleId : '', ruleIds: ruleIds, hasParams: !!(sampleId || q.get('rules')) };
  }

  var api = {
    lookupField: lookupField,
    matchRule: matchRule,
    scanRecords: scanRecords,
    parseRecords: parseRecords,
    buildShareUrl: buildShareUrl,
    parseShareParams: parseShareParams
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof document === 'undefined') return;

  var data = window.SIGMA_DATA || { samples: [], rules: [] };
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function selectedRuleIds() {
    return Array.prototype.slice.call(document.querySelectorAll('input[name="sigmaRule"]:checked')).map(function (el) { return el.value; });
  }
  function selectedRules() {
    var ids = selectedRuleIds();
    return data.rules.filter(function (r) { return ids.indexOf(r.id) !== -1; });
  }
  function currentSample() {
    var id = $('sampleSelect').value;
    for (var i = 0; i < data.samples.length; i++) if (data.samples[i].id === id) return data.samples[i];
    return null;
  }
  function setStatus(msg) { $('shareStatus').textContent = msg; }
  function renderFindings(findings, recordCount, ruleCount, label) {
    var box = $('results');
    var h = '<p class="sub">' + esc(label) + ': scanned ' + recordCount + ' record(s) with ' + ruleCount + ' rule(s); ' + findings.length + ' match(es).</p>';
    if (!findings.length) {
      box.innerHTML = h + '<p>No matches.</p>';
      return;
    }
    findings.forEach(function (f) {
      h += '<div class="finding ' + esc(f.level) + '"><b>' + esc(f.ruleTitle) + '</b> ' +
        '<span class="risk-' + esc(f.level) + '">' + esc(f.level) + '</span>' +
        '<div class="meta">record #' + (f.recordIndex + 1) + ' · ' + esc(f.actor) + (f.time ? ' · ' + esc(f.time) : '') + (f.event ? ' · ' + esc(f.event) : '') + '</div></div>';
    });
    box.innerHTML = h;
  }
  function run() {
    var rules = selectedRules();
    if (!rules.length) { $('results').innerHTML = '<p>Select at least one rule.</p>'; return; }
    var sampleId = $('sampleSelect').value;
    var records;
    var label;
    try {
      if (sampleId === 'custom') {
        records = parseRecords($('customJson').value || '');
        label = 'Custom pasted JSON';
      } else {
        var sample = currentSample();
        if (!sample) throw new Error('Unknown sample.');
        records = sample.records;
        label = sample.label;
      }
    } catch (e) {
      $('results').innerHTML = '<p>Could not parse JSON: ' + esc(e.message) + '</p>';
      return;
    }
    renderFindings(scanRecords(records, rules), records.length, rules.length, label);
  }
  function copyLink() {
    var sampleId = $('sampleSelect').value;
    if (sampleId === 'custom') {
      setStatus('Share links only include shipped samples and rules. Custom input stays in this browser and is not copied.');
      return;
    }
    var url = buildShareUrl(window.location.href, sampleId, selectedRuleIds());
    function done() { setStatus('Link copied: ' + url); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(done, function () { window.prompt('Copy this link:', url); done(); });
    } else {
      window.prompt('Copy this link:', url);
      done();
    }
  }
  function buildControls() {
    var sel = $('sampleSelect');
    data.samples.forEach(function (s) {
      var o = document.createElement('option');
      o.value = s.id;
      o.textContent = s.label + ' (synthetic training data)';
      sel.appendChild(o);
    });
    var custom = document.createElement('option');
    custom.value = 'custom';
    custom.textContent = 'Custom pasted JSON';
    sel.appendChild(custom);

    var list = $('ruleList');
    data.rules.forEach(function (r) {
      var label = document.createElement('label');
      label.className = 'rule-choice';
      label.innerHTML = '<input type="checkbox" name="sigmaRule" value="' + esc(r.id) + '" checked> ' +
        '<b>' + esc(r.title) + '</b> <span class="risk-' + esc(r.level) + '">' + esc(r.level) + '</span>' +
        '<span class="sub"> — ' + esc(r.description) + '</span>';
      list.appendChild(label);
    });

    var shared = parseShareParams(window.location.search, data);
    if (shared.sampleId) sel.value = shared.sampleId;
    if (shared.ruleIds.length) {
      Array.prototype.forEach.call(document.querySelectorAll('input[name="sigmaRule"]'), function (el) {
        el.checked = shared.ruleIds.indexOf(el.value) !== -1;
      });
    }
    $('runSigma').addEventListener('click', run);
    $('copySigmaLink').addEventListener('click', copyLink);
    sel.addEventListener('change', function () {
      $('customWrap').hidden = sel.value !== 'custom';
    });
    $('customWrap').hidden = sel.value !== 'custom';
    if (shared.hasParams && shared.sampleId) run();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildControls);
  else buildControls();
})();
