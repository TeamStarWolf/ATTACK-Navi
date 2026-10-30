// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Links into OWASP OpenCRE (https://opencre.org), which links security standards to
 * each other through common requirements: a CWE or CAPEC entry can be followed to OWASP
 * ASVS requirements, Cheat Sheets, Web Security Testing Guide sections and other
 * standards. OpenCRE has no ATT&CK data, and it reaches CAPEC only through each
 * pattern's related CWE entries.
 *
 * The links use OpenCRE's smartlink route, which redirects to the one CRE linked to the
 * entry, to OpenCRE's page for the entry when several are linked, or to the entry on
 * cwe.mitre.org or capec.mitre.org when OpenCRE has no links for it, so a link does not
 * dead-end on an unmapped id. The behaviour was read from smartlink() in OpenCRE's
 * application/web/web_main.py (OWASP/OpenCRE at cbf22e0, 2026-10-26); the live site was
 * not reachable from the environment this was written in.
 */

export const OPENCRE_SMARTLINK_BASE = 'https://opencre.org/smartlink/standard';

export type OpenCreStandard = 'CWE' | 'CAPEC';

/**
 * OpenCRE smartlink for a CWE or CAPEC id, given as "CWE-79", "CAPEC-66" or the bare
 * number. Returns null when the id is not one of the standard's ids (no number, or the
 * other standard's prefix), so the caller renders no link.
 */
export function openCreSmartlink(standard: OpenCreStandard, id: string | null | undefined): string | null {
  const num = new RegExp(`^(?:${standard}-)?(\\d+)$`, 'i').exec((id ?? '').trim())?.[1];
  return num ? `${OPENCRE_SMARTLINK_BASE}/${standard}/${num}` : null;
}
