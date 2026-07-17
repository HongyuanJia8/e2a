"use client";

// Renders an untrusted email HTML body safely. Two layers of defense:
//   1. DOMPurify strips scripts, event handlers, and dangerous tags/attrs.
//   2. The cleaned markup is rendered inside a sandboxed <iframe srcdoc> with
//      NO allow-scripts — so even if something slipped past the sanitizer it
//      cannot execute, touch cookies, or reach the dashboard DOM.
//
// Inline images (attachments the body references by a `cid:` URL — e.g. a
// pasted screenshot) are resolved to data:/blob: URLs of the fetched bytes and
// rendered BY DEFAULT: they travelled with the mail and are not a remote
// tracking vector. Remote http(s) images ARE blocked by default (tracking-pixel
// / read-receipt defense, the Gmail convention) and loaded only when the user
// opts in.
//
// The iframe keeps `allow-same-origin` (so we can measure its content height to
// auto-size) and `allow-popups` (so sanitized links can open in a new tab via
// the injected `<base target="_blank">`). It deliberately omits allow-scripts
// and allow-forms.

import DOMPurify from "dompurify";
import { useEffect, useMemo, useRef, useState } from "react";
import { loadInlineAttachmentUrl } from "../onboarding/api";
import type { AttachmentMeta } from "../types";
import { findCidRefs, rewriteCidImages } from "./inlineImages";

// isRemoteUrl reports whether a single URL points off-origin over the network
// (http/https/protocol-relative). data:/relative URLs are NOT remote — a data:
// URL is self-contained (an inline image we resolved) and must survive the
// remote-image block. Scheme is checked at the START so a "//" inside base64
// data can't be mistaken for a protocol-relative host.
function isRemoteUrl(v: string): boolean {
  const s = v.trim().toLowerCase();
  return s.startsWith("http://") || s.startsWith("https://") || s.startsWith("//");
}

// isRemoteSrcset reports whether a srcset (comma-separated `url descriptor`
// candidates) references any remote URL.
function isRemoteSrcset(v: string): boolean {
  return v.split(",").some((cand) => isRemoteUrl(cand.trim().split(/\s+/)[0] ?? ""));
}

// sanitizeEmail cleans the raw email HTML. When showImages is false it also
// neutralizes REMOTE image sources (img src/srcset and CSS url() backgrounds)
// while leaving already-resolved inline data:/blob: images intact, reporting
// whether any remote resource was actually blocked so the caller can offer a
// "Load images" affordance only when it matters.
function sanitizeEmail(
  html: string,
  showImages: boolean,
): { clean: string; blockedRemote: boolean } {
  let blockedRemote = false;

  DOMPurify.addHook("afterSanitizeAttributes", (node) => {
    const el = node as Element;
    // Force links to open in a new tab and drop the referrer/opener.
    if (el.tagName === "A") {
      el.setAttribute("target", "_blank");
      el.setAttribute("rel", "noopener noreferrer nofollow");
    }
    if (!showImages) {
      // Strip only REMOTE resource carriers so inline (data:/blob:) images we
      // resolved still render; blockedRemote reflects what was actually blocked.
      // This is the belt; the CSP injected in wrapDocument is the authoritative
      // block that also covers CSS-escaped url() and any vector missed here.
      for (const attr of ["src", "background", "poster"] as const) {
        const val = el.getAttribute?.(attr);
        if (val && isRemoteUrl(val)) {
          blockedRemote = true;
          el.removeAttribute(attr);
        }
      }
      const srcset = el.getAttribute?.("srcset");
      if (srcset && isRemoteSrcset(srcset)) {
        blockedRemote = true;
        el.removeAttribute("srcset");
      }
      const style = el.getAttribute?.("style");
      if (style && /url\s*\(/i.test(style)) {
        // Neutralize only remote url()s; keep inline data:/blob: backgrounds.
        const next = style.replace(/url\s*\(\s*(['"]?)([^)'"]*)\1\s*\)/gi, (whole, _q, inner) => {
          if (isRemoteUrl(inner)) {
            blockedRemote = true;
            return "none";
          }
          return whole;
        });
        el.setAttribute("style", next);
      }
    }
  });

  const clean = DOMPurify.sanitize(html, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["script", "iframe", "object", "embed", "form", "input", "button", "base"],
    ADD_ATTR: ["target"],
  });

  DOMPurify.removeHook("afterSanitizeAttributes");
  return { clean: String(clean), blockedRemote };
}

// wrapDocument builds the full srcdoc: a forced-light surface (email HTML
// assumes a white background regardless of the dashboard theme), responsive
// images, and a base target so links open in a new tab.
//
// The Content-Security-Policy is the AUTHORITATIVE control, not the DOMPurify
// hook: `default-src 'none'` blocks scripts/frames/objects/fetches outright.
// Inline images (resolved to data: URLs) are always allowed — they are trusted
// content that travelled with the mail; only when the user loads images does
// `img-src` gain http:/https:, defeating remote-tracking vectors until then.
function wrapDocument(innerHTML: string, showImages: boolean): string {
  const csp = showImages
    ? "default-src 'none'; img-src http: https: data:; media-src http: https: data:; style-src 'unsafe-inline'; font-src http: https: data:"
    : "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:";
  return (
    "<!doctype html><html><head><meta charset=\"utf-8\">" +
    "<meta http-equiv=\"Content-Security-Policy\" content=\"" + csp + "\">" +
    "<meta name=\"referrer\" content=\"no-referrer\">" +
    "<base target=\"_blank\">" +
    "<style>" +
    "html,body{margin:0;padding:0;}" +
    "body{background:#fff;color:#1a1a1a;" +
    "font:13.5px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;" +
    "word-break:break-word;overflow-wrap:anywhere;}" +
    "img{max-width:100%;height:auto;}" +
    "table{max-width:100%;}" +
    "a{color:#2563eb;}" +
    "</style></head><body>" +
    innerHTML +
    "</body></html>"
  );
}

export function EmailHtmlBody({
  html,
  attachments,
  email,
  messageId,
}: {
  html: string;
  attachments?: AttachmentMeta[];
  email?: string;
  messageId?: string;
}) {
  const [showImages, setShowImages] = useState(false);
  const [cidUrls, setCidUrls] = useState<Map<string, string>>(() => new Map());
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // Resolve inline (cid:) images: match each `cid:` reference in the body to an
  // attachment by content_id, fetch its bytes as a data: URL, and build a
  // cid→URL map. Runs whenever the body or its attachment set changes; a
  // cancelled flag drops results from a superseded run. No-op when we lack the
  // message coordinates needed to fetch bytes.
  useEffect(() => {
    if (!email || !messageId) return;
    const refs = findCidRefs(html);
    if (refs.size === 0) return;
    const inline = (attachments ?? []).filter(
      (a) => a.content_id && refs.has(a.content_id),
    );
    if (inline.length === 0) return;

    let cancelled = false;
    (async () => {
      const resolved = new Map<string, string>();
      await Promise.all(
        inline.map(async (a) => {
          try {
            const { url } = await loadInlineAttachmentUrl(email, messageId, a);
            if (!cancelled) resolved.set(a.content_id as string, url);
          } catch {
            /* leave this image unresolved — it degrades to a broken icon */
          }
        }),
      );
      if (!cancelled && resolved.size > 0) setCidUrls(resolved);
    })();

    return () => {
      cancelled = true;
    };
  }, [html, attachments, email, messageId]);

  const resolvedHtml = useMemo(() => rewriteCidImages(html, cidUrls), [html, cidUrls]);

  const { clean, blockedRemote } = useMemo(
    () => sanitizeEmail(resolvedHtml, showImages),
    [resolvedHtml, showImages],
  );
  const srcDoc = useMemo(() => wrapDocument(clean, showImages), [clean, showImages]);

  // Auto-size the iframe to its content. Needs allow-same-origin to read the
  // content document; re-measures on reflow (e.g. late-loading images).
  useEffect(() => {
    const frame = iframeRef.current;
    if (!frame) return;
    let observer: ResizeObserver | undefined;
    const fit = () => {
      try {
        const doc = frame.contentDocument;
        if (doc?.documentElement) {
          frame.style.height = `${doc.documentElement.scrollHeight}px`;
        }
      } catch {
        /* cross-origin guard; ignore */
      }
    };
    const onLoad = () => {
      fit();
      try {
        const doc = frame.contentDocument;
        if (doc?.documentElement && typeof ResizeObserver !== "undefined") {
          observer = new ResizeObserver(fit);
          observer.observe(doc.documentElement);
        }
      } catch {
        /* ignore */
      }
    };
    frame.addEventListener("load", onLoad);
    fit();
    return () => {
      frame.removeEventListener("load", onLoad);
      observer?.disconnect();
    };
  }, [srcDoc]);

  return (
    <div>
      {blockedRemote && !showImages && (
        <div
          className="flex items-center"
          style={{
            gap: 10,
            marginBottom: 10,
            padding: "7px 11px",
            fontSize: 12,
            color: "var(--fg-muted)",
            background: "var(--bg-elev)",
            border: "1px solid var(--border-sub)",
            borderRadius: "var(--r-sm)",
          }}
        >
          <span>Remote images blocked to protect your privacy.</span>
          <button
            type="button"
            onClick={() => setShowImages(true)}
            style={{
              color: "var(--accent-strong)",
              background: "transparent",
              border: "none",
              padding: 0,
              cursor: "pointer",
              fontWeight: 600,
            }}
          >
            Load images
          </button>
        </div>
      )}
      <iframe
        ref={iframeRef}
        title="Email body"
        sandbox="allow-same-origin allow-popups"
        srcDoc={srcDoc}
        style={{
          display: "block",
          width: "100%",
          border: "none",
          background: "#fff",
          borderRadius: "var(--r-sm)",
        }}
      />
    </div>
  );
}
