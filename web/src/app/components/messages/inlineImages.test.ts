import { findCidRefs, rewriteCidImages } from "./inlineImages";

describe("findCidRefs", () => {
  it("extracts cid tokens from img src (both quote styles)", () => {
    const html =
      '<img src="cid:ii_a@mail.gmail.com"> <img src=\'cid:logo\'>';
    expect(findCidRefs(html)).toEqual(new Set(["ii_a@mail.gmail.com", "logo"]));
  });

  it("extracts cid tokens from CSS url() backgrounds", () => {
    expect(findCidRefs('<td style="background:url(cid:bg1)">')).toEqual(
      new Set(["bg1"]),
    );
  });

  it("returns an empty set when there are no cid references", () => {
    expect(findCidRefs('<img src="https://x/y.png"><p>hi</p>').size).toBe(0);
  });
});

describe("rewriteCidImages", () => {
  it("replaces each cid reference with its resolved url", () => {
    const html = '<img src="cid:a"><img src="cid:b">';
    const out = rewriteCidImages(
      html,
      new Map([
        ["a", "data:image/png;base64,AAA"],
        ["b", "blob:http://app/xyz"],
      ]),
    );
    expect(out).toBe(
      '<img src="data:image/png;base64,AAA"><img src="blob:http://app/xyz">',
    );
    expect(out).not.toContain("cid:");
  });

  it("leaves unresolved cid references untouched", () => {
    const html = '<img src="cid:known"><img src="cid:missing">';
    const out = rewriteCidImages(html, new Map([["known", "data:x"]]));
    expect(out).toContain("data:x");
    expect(out).toContain("cid:missing");
  });

  it("is a no-op when the url map is empty", () => {
    const html = '<img src="cid:a">';
    expect(rewriteCidImages(html, new Map())).toBe(html);
  });
});
