// SCAMWISE analysis engine (ES module, no dependencies).
// Used by: the `analyze` edge function (Deno), the public website demo, and the Node test suite.
// The Android app runs a Dart port that reads the same rules.json for offline scans.
//
// Design rules:
//   * Transparent: every point of score comes from a named indicator with an explanation.
//   * Never claims "safe": absence of evidence is reported as Low or Inconclusive, with caveats.
//   * Never visits links: URLs are parsed as strings only.
//   * Secrets first: authentication codes / card numbers are redacted before anything else.

export function createEngine(rules) {
  const ci = (p) => new RegExp(p, 'gi');
  const textRules = rules.text_rules.map((r) => ({ ...r, res: r.patterns.map(ci) }));
  const ur = rules.url_rules;
  const W = ur.weights;
  const authKw = new RegExp(rules.auth_code.keywords, 'i');
  const authExclude = new RegExp(rules.auth_code.exclude_before + '\\W{0,3}(is\\W{0,3}|no\\.?\\W{0,3}|number\\W{0,3})?$', 'i');
  const sensitivePath = new RegExp(ur.sensitive_path, 'i');
  const negation = new RegExp(rules.negation_window, 'i');
  const commonTlds = new Set(['com','in','net','org','co','io','info','biz','me','app','dev','ai','us','uk','ru','cn','tv','ly','gl','gd','at','to','ws','id','ph','pk','bd','np','lk','ae','sg','my','au','ca','de','fr','eu','page','bank','gov','edu','store','tech','club','cloud','digital','today','news','net.in','co.in']
    .concat(ur.suspicious_tlds));

  // ------------------------------------------------------------ redaction
  function luhn(digits) {
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits.charCodeAt(i) - 48;
      if (alt) { d *= 2; if (d > 9) d -= 9; }
      sum += d; alt = !alt;
    }
    return sum % 10 === 0;
  }

  function redact(input) {
    let text = String(input ?? '');
    const counts = { auth_code: 0, card: 0, password: 0, national_id: 0 };
    // codes already redacted on the phone before upload still count as an auth-code event
    counts.auth_code += (text.match(/\[REDACTED-CODE\]/g) || []).length;

    // card numbers (13-19 digits, Luhn-valid)
    text = text.replace(/\b(?:\d[ -]?){12,18}\d\b/g, (m) => {
      const d = m.replace(/\D/g, '');
      if (d.length >= 13 && d.length <= 19 && luhn(d)) { counts.card++; return '[REDACTED-CARD]'; }
      return m;
    });
    // Aadhaar-style 4-4-4
    text = text.replace(/\b\d{4}[ -]\d{4}[ -]\d{4}\b/g, () => { counts.national_id++; return '[REDACTED-ID]'; });
    // explicit passwords
    text = text.replace(/\b(password|passwd|pwd)(\s*(?:is|:|=|-)\s*)(\S+)/gi, (m, k, sep) => {
      counts.password++; return `${k}${sep}[REDACTED-PASSWORD]`;
    });
    // authentication codes: 4-8 digits (optionally prefixed like G-) near an OTP keyword
    text = text.replace(/\b([A-Z]{1,3}-)?(\d{4,8})\b/g, (m, prefix, digits, offset, whole) => {
      const before = whole.slice(Math.max(0, offset - 45), offset);
      const after = whole.slice(offset + m.length, offset + m.length + 30);
      if (/(rs\.?|₹|inr|usd|\$)\s*$/i.test(before)) return m;          // money, not a code
      if (/^\s*(rs|₹|inr|rupees|\/-)/i.test(after)) return m;
      if (/^[ ]?(am|pm|hrs)\b/i.test(after)) return m;                  // times
      if (!(authKw.test(before) || authKw.test(after) || prefix)) return m;
      if (authExclude.test(before)) return m;                           // "pin code 560001", "a/c XX1234"
      counts.auth_code++;
      return (prefix || '') + '[REDACTED-CODE]';
    });
    return { text, counts, containedAuthCode: counts.auth_code > 0 };
  }

  // extra masking for anything that will be stored (opt-in excerpt only)
  function maskForStorage(text) {
    return text
      .replace(/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, '[EMAIL]')
      .replace(/(\+?\d[\d -]{8,}\d)/g, '[NUMBER]')
      .replace(/https?:\/\//gi, (m) => m.replace(/t/gi, 'x'))            // defang
      .slice(0, 280);
  }

  // ------------------------------------------------------------ URLs
  function registrable(host) {
    const labels = host.split('.');
    const last2 = labels.slice(-2).join('.');
    if (ur.multi_part_suffixes.includes(last2) && labels.length >= 3) return labels.slice(-3).join('.');
    return last2;
  }
  const isOfficial = (host) => ur.official_domains.some((d) => host === d || host.endsWith('.' + d));

  function extractUrls(text) {
    const re = /\b((?:https?|hxxps?):\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{2,5})?(?:\/[^\s<>"'`]*)?)/gi;
    const out = []; const seen = new Set(); let m;
    while ((m = re.exec(text)) !== null) {
      let raw = m[1].replace(/[.,;:!?)\]}'"]+$/, '');
      const hasScheme = /^(https?|hxxps?):\/\//i.test(raw);
      const isWww = /^www\./i.test(raw);
      let parsed;
      try { parsed = new URL((hasScheme ? raw.replace(/^hxxp/i, 'http') : 'http://' + raw)); } catch { continue; }
      const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
      const tld = host.split('.').pop();
      if (!hasScheme && !isWww && !commonTlds.has(tld)) continue;      // "report.pdf", "e.g."
      if (!host.includes('.') && !/^\[/.test(host)) continue;
      if (seen.has(raw.toLowerCase())) continue;
      seen.add(raw.toLowerCase());
      out.push({ raw, hasScheme, scheme: hasScheme ? parsed.protocol.replace(':', '') : null, host, parsed });
      if (out.length >= 10) break;
    }
    return out;
  }

  function urlFlags(u) {
    const flags = [];
    const host = u.host;
    const domain = registrable(host);
    const official = isOfficial(host);
    const labels = host.split('.');
    const pathq = (u.parsed.pathname + u.parsed.search).toLowerCase();
    const add = (code, detail) => flags.push({ code, detail });

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) add('url_ip_host', `Link points to a raw IP address (${host}) instead of a named website`);
    if (host.includes('xn--')) add('url_punycode', `Internationalised (punycode) domain that can imitate familiar letters: ${host}`);
    if (u.parsed.username || /^[^/]*@/.test(u.raw.replace(/^\w+:\/\//, ''))) add('url_at_symbol', 'Link contains "@", which hides the real destination');
    if (ur.shorteners.includes(domain) || ur.shorteners.includes(host)) add('url_shortener', `Shortened link (${host}) hides the real destination`);
    if (ur.suspicious_tlds.includes(labels[labels.length - 1])) add('url_suspicious_tld', `Uses the ".${labels[labels.length - 1]}" ending, which is common in throwaway scam sites`);
    if (!official) {
      const tokens = host.split(/[.-]/);
      const brand = ur.brands.find((b) => tokens.includes(b) || (b.length >= 5 && host.includes(b)));
      if (brand) add('url_brand_mismatch', `Mentions "${brand}" but is not that organisation's official domain (${domain})`);
      if (sensitivePath.test(pathq) || sensitivePath.test(host)) add('url_sensitive_path', 'Link leads to a login / verify / KYC style page on an unofficial site');
    }
    if (labels.length - domain.split('.').length >= 3) add('url_many_subdomains', `Unusually deep sub-domain chain (${host})`);
    if (u.scheme === 'http') add('url_http_only', 'Unencrypted http:// link');
    if (/\.apk(\?|#|$)/i.test(u.parsed.pathname)) add('url_apk', 'Link downloads an Android app (.apk) from outside the Play Store');
    if (u.raw.length > 120) add('url_long', 'Very long, obfuscated link');
    if ((domain.split('.')[0].match(/-/g) || []).length >= 2) add('url_hyphenated_domain', `Hyphen-heavy domain (${domain}) often used to imitate real brands`);
    if (u.parsed.port && !['80', '443'].includes(u.parsed.port)) add('url_odd_port', `Uses a non-standard port (:${u.parsed.port})`);
    return { domain, official, flags };
  }

  const URL_LABELS = {
    url_ip_host: 'Link uses a raw IP address', url_punycode: 'Look-alike (punycode) domain',
    url_at_symbol: 'Link hides its real destination with "@"', url_shortener: 'Shortened link',
    url_suspicious_tld: 'High-risk domain ending', url_brand_mismatch: 'Brand name on an unofficial domain',
    url_many_subdomains: 'Deep sub-domain chain', url_http_only: 'Unencrypted link',
    url_sensitive_path: 'Login / verification page on an unofficial site', url_apk: 'Direct app (.apk) download',
    url_long: 'Obfuscated long link', url_hyphenated_domain: 'Hyphen-heavy look-alike domain',
    url_odd_port: 'Non-standard port', known_malicious_url: 'Link is listed in the URLhaus malware database',
  };
  const URL_ADVICE = 'Do not open the link. Type the official website address yourself or use the official app.';

  const defang = (s) => s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');

  // ------------------------------------------------------------ main
  // ti = { status: 'match'|'no_match'|'unavailable'|'not_configured'|'error'|'not_applicable', matches: [...], detail }
  /** @param {string} input @param {{ ti?: any }} [opts] */
  function analyze(input, opts = {}) {
    const ti = opts.ti ?? null;
    const red = redact(input);
    const text = red.text;
    const urls = extractUrls(text);
    const indicators = [];
    const snippet = (s) => s.replace(/\s+/g, ' ').trim().slice(0, 80);

    // first match per rule; for "negatable" rules skip protective phrasing like "do not share this OTP"
    const firstMatch = (r, re) => {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        const before = text.slice(Math.max(0, m.index - 30), m.index);
        if (!(r.negatable && negation.test(before))) return m;
        if (m[0].length === 0) re.lastIndex++;
      }
      return null;
    };
    for (const r of textRules) {
      for (const re of r.res) {
        const m = firstMatch(r, re);
        if (m) {
          indicators.push({ code: r.code, family: r.family, weight: r.weight, label: r.label, advice: r.advice, detail: `Matched: "${snippet(m[0])}"` });
          break;
        }
      }
    }
    if (red.containedAuthCode) {
      const a = rules.auth_code;
      indicators.push({ code: a.code, family: a.family, weight: a.weight, label: a.label, advice: a.advice,
        detail: `${red.counts.auth_code} code(s) redacted on this device before analysis` });
    }

    const urlReports = urls.map((u) => {
      const f = urlFlags(u);
      return { display: defang(u.raw), host: u.host, domain: f.domain, official: f.official, flags: f.flags.map((x) => x.code), _flags: f.flags };
    });
    const urlCodes = new Map();
    for (const r of urlReports) for (const fl of r._flags) if (!urlCodes.has(fl.code)) urlCodes.set(fl.code, fl.detail);
    for (const [code, detail] of urlCodes) {
      indicators.push({ code, family: 'suspicious_link', weight: W[code] ?? 5, label: URL_LABELS[code] ?? code, advice: URL_ADVICE, detail });
    }

    const tiStatus = urls.length === 0 ? 'not_applicable' : (ti?.status ?? 'not_configured');
    if (tiStatus === 'match') {
      const first = ti.matches?.[0] ?? {};
      indicators.push({ code: 'known_malicious_url', family: 'known_threat', weight: W.known_malicious_url,
        label: URL_LABELS.known_malicious_url, advice: URL_ADVICE,
        detail: `URLhaus ${first.match_type ?? 'match'}: ${first.threat ?? 'malware distribution'}${first.url_status ? ` (status: ${first.url_status})` : ''}` });
    }

    // ---------------- scoring
    let score = indicators.reduce((s, i) => s + i.weight, 0);
    const has = (c) => indicators.some((i) => i.code === c);
    if (has('credential_request') && (has('urgency') || has('account_threat') || urls.length > 0)) {
      score += 10;
      indicators.push({ code: 'combo_credential_pressure', family: 'phishing', weight: 10,
        label: 'Credential request combined with pressure or a link', advice: 'This combination is the core pattern of phishing.', detail: 'Combination bonus' });
    }
    if ((has('prize_lure') || has('job_scam')) && has('payment_request')) {
      score += 15;
      indicators.push({ code: 'combo_advance_fee', family: 'payment_fraud', weight: 15,
        label: 'Reward or job offer that requires you to pay first', advice: 'Paying a fee to receive a prize, refund or salary is the defining pattern of advance-fee fraud.', detail: 'Combination bonus' });
    }
    if (red.containedAuthCode) score = Math.max(score, rules.auth_code.min_score);
    if (tiStatus === 'match') score = Math.max(score, 90);
    score = Math.min(100, score);

    // ---------------- classification
    const meaningful = text.replace(/\[REDACTED-[A-Z]+\]/g, '').replace(/\W+/g, '');
    let risk; const caveats = [];
    if (score >= rules.thresholds.high) risk = 'high';
    else if (score >= rules.thresholds.medium) risk = 'medium';
    else if (score > 0) risk = 'low';
    else if (meaningful.length < 12 && urls.length === 0) { risk = 'inconclusive'; caveats.push('There is too little content to assess.'); }
    else if (urls.length > 0 && tiStatus !== 'no_match') { risk = 'inconclusive'; caveats.push('No warning signs in the text, but the link could not be checked against threat intelligence.'); }
    else risk = 'low';
    // a weak signal plus an unverified link is not enough to call it low risk
    if (risk === 'low' && urls.length > 0 && tiStatus !== 'no_match') {
      risk = 'inconclusive';
      caveats.push('Some minor warning signs, and the link reputation could not be verified.');
    }

    if (urls.length > 0) {
      if (tiStatus === 'no_match') caveats.push('URLhaus has no record of this link. That does NOT mean it is safe; new scam sites appear every day.');
      else if (tiStatus === 'not_configured') caveats.push('Threat-intelligence lookup is not configured, so link reputation was NOT checked.');
      else if (tiStatus === 'unavailable' || tiStatus === 'error') caveats.push('The threat-intelligence service could not be reached, so link reputation was NOT checked.');
    }
    if (risk === 'low') caveats.push('Low risk means no strong scam pattern was found, not that the message is guaranteed safe.');

    // ---------------- category
    let category = 'none';
    if (tiStatus === 'match') category = 'known_threat';
    else if (indicators.length) {
      const byFam = {};
      for (const i of indicators) if (i.family !== 'pressure') byFam[i.family] = (byFam[i.family] || 0) + i.weight;
      // links support the story told by the text, so prefer a text-based family when one exists
      const ranked = Object.entries(byFam).sort((a, b) => b[1] - a[1]);
      const textFam = ranked.find(([f]) => f !== 'suspicious_link');
      const top = textFam ?? ranked[0];
      category = top ? top[0] : 'pressure';
    }
    const familyLabels = { ...rules.families, pressure: rules.families.pressure };

    const summary = {
      high: 'High risk: several strong scam indicators. Do not click links, pay, or share any code.',
      medium: 'Medium risk: there are warning signs. Verify through an official channel before acting.',
      low: 'Low risk: no strong scam indicators were found.',
      inconclusive: 'Inconclusive: there is not enough evidence to judge this message.',
    }[risk];

    const recommendations = [...new Set(indicators.filter((i) => i.weight >= 10).map((i) => i.advice))].slice(0, 4);
    if (risk === 'high' || risk === 'medium') recommendations.push('If you already shared details or paid, call your bank immediately and report it at cybercrime.gov.in or helpline 1930.');

    indicators.sort((a, b) => b.weight - a.weight);
    return {
      engine_version: rules.version,
      risk_level: risk,
      score,
      category,
      category_label: familyLabels[category] ?? category,
      summary,
      indicators,
      urls: urlReports.map(({ _flags, ...r }) => r),
      domains: [...new Set(urlReports.map((r) => r.domain))],
      ti_status: tiStatus,
      contained_auth_code: red.containedAuthCode,
      redaction_counts: red.counts,
      redacted_text: text,
      caveats,
      recommendations,
    };
  }

  return { analyze, redact, extractUrls, maskForStorage, registrable, defang };
}
