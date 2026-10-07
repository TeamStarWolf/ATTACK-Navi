// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/** Header the credentials proxy (server/) requires on every /api/* request. */
export const PROXY_CLIENT_HEADER = 'X-Requested-With';
export const PROXY_CLIENT_VALUE = 'ATTACK-Navi';
/** Header carrying the operator's PROXY_AUTH_TOKEN (Settings > Integrations). */
export const PROXY_TOKEN_HEADER = 'X-Proxy-Key';

/**
 * Headers every proxy-mode OpenCTI/MISP request carries: the custom header the
 * proxy demands (forces a CORS preflight for cross-origin callers) and, when the
 * operator has entered one, the proxy access token. Never sent in direct mode.
 */
export function proxyRequestHeaders(proxyToken: string | undefined): Record<string, string> {
  const headers: Record<string, string> = { [PROXY_CLIENT_HEADER]: PROXY_CLIENT_VALUE };
  const token = (proxyToken ?? '').trim();
  if (token) headers[PROXY_TOKEN_HEADER] = token;
  return headers;
}
