// Pure helpers for resolving inline (cid:) images in an email HTML body.
//
// Mail clients embed pasted images as a MIME part referenced from the HTML by a
// Content-ID URL — `<img src="cid:ii_abc@mail.gmail.com">` (or `url(cid:…)` in a
// CSS background). The browser can't resolve `cid:` in a web document, so these
// must be rewritten to a real URL (a data: or blob: URL of the fetched bytes)
// before the HTML is rendered. These helpers are the pure string half of that;
// the byte-fetching + React wiring lives in EmailHtmlBody.

// Matches a `cid:` reference and captures the Content-ID token — the part after
// `cid:` up to the closing quote, whitespace, `)` (CSS url()), or `>`. Covers
// both `src="cid:X"` and `url(cid:X)` forms.
const CID_REF = /cid:([^"'\s)>]+)/gi;

// findCidRefs returns the distinct Content-ID tokens referenced by `cid:` URLs
// in the HTML (empty set when there are none).
export function findCidRefs(html: string): Set<string> {
  const out = new Set<string>();
  for (const m of html.matchAll(CID_REF)) {
    if (m[1]) out.add(m[1]);
  }
  return out;
}

// rewriteCidImages replaces every `cid:<id>` reference whose id is present in
// `urls` with the resolved URL. References with no entry (bytes unavailable) are
// left untouched — they degrade to a broken image, exactly as before.
export function rewriteCidImages(html: string, urls: Map<string, string>): string {
  if (urls.size === 0) return html;
  return html.replace(CID_REF, (whole, id: string) => urls.get(id) ?? whole);
}
