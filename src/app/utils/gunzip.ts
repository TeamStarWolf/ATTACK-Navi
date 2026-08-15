// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Decompress a gzip payload to text using the browser-native
 * DecompressionStream (Chrome 80+, Firefox 113+, Safari 16.4+).
 * Throws if the stream is corrupt or the API is unavailable.
 */
export async function gunzipToText(buffer: ArrayBuffer): Promise<string> {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('DecompressionStream is not supported in this browser');
  }
  const stream = new Blob([buffer]).stream().pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).text();
}
