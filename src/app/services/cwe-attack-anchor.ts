// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Shared CWE->ATT&CK exploitation-anchor correction. Pure, framework-free logic so it
// is used identically by the runtime (cve.service.mapCwesToAttackIds) and mirrored by
// the static generator (scripts/build-cve-technique-map.mjs) from the SAME data asset
// (assets/data/cwe-exploitation-anchor.json) — they cannot drift.
//
// WHY: a plain CWE->CAPEC->ATT&CK fan-out over-attributes generic evasion/credential
// techniques (e.g. T1539, T1574.006/.007, T1562.003 to 100k+ CVEs each) and omits the
// techniques that actually fit a vuln (T1190/T1059 were entirely absent). This anchors
// the mapping on the EXPLOITATION NATURE of the vulnerability (high confidence) while
// keeping the CAPEC-derived set as a low-confidence supplement, and suppresses the noisy
// fan-out for broad/pillar CWEs.

export interface ExploitationClass {
  techniques: string[];
  cwes: string[];
  rationale?: string;
}

export interface AnchorData {
  exploitationClasses: Record<string, ExploitationClass>;
  genericCwes: string[];
  /** Post-exploitation techniques never derivable from a CWE — dropped from the low-confidence tier. */
  suppressTechniques?: string[];
  rceKeywords?: string[];
  rceTechniques?: string[];
  remoteAccessApplianceKeywords: string[];
  remoteAccessTechniques: string[];
}

export interface CorrectionResult {
  /** High-confidence techniques from the exploitation-nature anchor. */
  high: string[];
  /** Low-confidence techniques from the CWE->CAPEC->ATT&CK chain (generic CWEs suppressed). */
  low: string[];
  /** Union, anchor-first, deduped — the flat list consumers use as mappedAttackIds. */
  all: string[];
}

/** Normalize "CWE-78" / "cwe-78" / "78" -> "78". */
export function cweNum(cwe: string): string {
  return String(cwe).replace(/^CWE-/i, '').trim();
}

/**
 * Correct a CVE's CWE-derived ATT&CK techniques with the exploitation anchor.
 * @param cwes             the CVE's CWEs (any form: "CWE-78" or "78")
 * @param capecDerivedFor  fn returning the CAPEC-chain techniques for one CWE (may be [])
 * @param anchor           the loaded anchor data
 * @param ctx.text         optional CVE text (description + CPEs) for the remote-access-appliance hint
 */
export function correctCveTechniques(
  cwes: string[],
  capecDerivedFor: (cwe: string) => string[],
  anchor: AnchorData,
  ctx?: { text?: string },
): CorrectionResult {
  const generic = new Set((anchor.genericCwes || []).map(String));
  const classes = Object.values(anchor.exploitationClasses || {});
  const anchorTechForCwe = (num: string): string[] => {
    const out: string[] = [];
    for (const c of classes) if (c.cwes.includes(num)) out.push(...c.techniques);
    return out;
  };

  const high = new Set<string>();
  const low = new Set<string>();
  let anyExploitation = false;

  for (const cwe of cwes || []) {
    const num = cweNum(cwe);
    const anchored = anchorTechForCwe(num);
    if (anchored.length) {
      anyExploitation = true;
      for (const t of anchored) high.add(t);
    }
    // Suppress the noisy CAPEC fan-out for broad/pillar CWEs; keep it (low-confidence) otherwise.
    if (!generic.has(num)) {
      for (const t of capecDerivedFor(cwe) || []) low.add(t);
    }
  }

  if (anyExploitation && ctx?.text) {
    const t = ctx.text.toLowerCase();
    // Explicit RCE indication -> Command and Scripting Interpreter (the execution mechanism).
    // Context-gated so a broad CWE (e.g. CWE-20 covering XSS/DoS/RCE) only gets T1059 on real RCE.
    if ((anchor.rceKeywords || []).some(k => t.includes(k))) {
      for (const x of anchor.rceTechniques || []) high.add(x);
    }
    // Remote-access appliance (VPN/gateway/NetScaler/etc.) exploitation also implicates
    // External Remote Services.
    if ((anchor.remoteAccessApplianceKeywords || []).some(k => t.includes(k))) {
      for (const x of anchor.remoteAccessTechniques || []) high.add(x);
    }
  }

  for (const t of high) low.delete(t);
  // Drop adversary post-exploitation techniques that a CWE can't imply (fan-out artifacts).
  for (const t of anchor.suppressTechniques || []) low.delete(t);
  const highArr = [...high].sort();
  const lowArr = [...low].sort();
  // A confident exploitation anchor SUPERSEDES the noisy CAPEC fan-out: when we know how the
  // vuln is exploited, the broad CWE->CAPEC evasion/credential fan-out is noise for this CVE.
  // Non-exploitation CVEs (no anchor) keep the CAPEC-derived set as their only (low-conf) signal,
  // which preserves genuine e.g. defense-evasion mappings.
  const all = highArr.length ? highArr : lowArr;
  return { high: highArr, low: lowArr, all };
}
