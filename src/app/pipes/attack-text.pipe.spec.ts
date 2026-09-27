// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { AttackTextPipe } from './attack-text.pipe';

/**
 * Regression tests for the XSS hardening of AttackTextPipe. These guard the security
 * property (no live markup escapes from untrusted description text) and the intended
 * rendering (citation stripping + safe https anchors).
 */
describe('AttackTextPipe', () => {
  const pipe = new AttackTextPipe();

  it('returns empty string for null/undefined/empty', () => {
    expect(pipe.transform(null)).toBe('');
    expect(pipe.transform(undefined)).toBe('');
    expect(pipe.transform('')).toBe('');
  });

  it('neutralizes a well-formed <img onerror> payload', () => {
    const out = pipe.transform('<img src=x onerror=alert(1)>');
    expect(out).not.toContain('<img');
    expect(out.toLowerCase()).not.toContain('onerror=');
  });

  it('neutralizes a malformed/unclosed tag (the regex-stripper bypass)', () => {
    const out = pipe.transform('lead <img src=x onerror=alert(1) trailing');
    expect(out).not.toContain('<img');
    expect(out.toLowerCase()).not.toContain('onerror=');
  });

  it('does not emit a live <script> element', () => {
    const out = pipe.transform('<script>alert(1)</script>visible');
    expect(out).not.toContain('<script');
    expect(out).toContain('visible');
  });

  it('removes ATT&CK citation markers', () => {
    expect(pipe.transform('foo (Citation: Vendor 2020) bar')).toBe('foo bar');
  });

  it('renders a safe anchor from an https markdown link', () => {
    const out = pipe.transform('see [the docs](https://example.com/a?x=1&y=2)');
    expect(out).toContain('<a href="https://example.com/a?x=1&amp;y=2"');
    expect(out).toContain('rel="noopener noreferrer"');
    expect(out).toContain('>the docs</a>');
  });

  it('does not build anchors for non-http(s) schemes', () => {
    const out = pipe.transform('[x](javascript:alert(1))');
    expect(out).not.toContain('<a ');
    expect(out.toLowerCase()).not.toContain('javascript:alert');
  });

  it('escapes stray angle brackets/quotes in plain text', () => {
    const out = pipe.transform('a < b && c "d"');
    expect(out).toContain('&lt;');
    expect(out).toContain('&amp;');
    expect(out).toContain('&quot;');
    expect(out).not.toContain('<b');
  });
});
