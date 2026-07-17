import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import {
  AttachmentChips,
  downloadableAttachments,
} from "./AttachmentChips";
import type { AttachmentMeta } from "../types";

jest.mock("../onboarding/api", () => ({
  getAttachment: jest.fn(),
}));
import { getAttachment } from "../onboarding/api";

const inlineImg: AttachmentMeta = {
  index: 0,
  filename: "image.png",
  content_type: "image/png",
  size_bytes: 1000,
  content_id: "ii_a@mail",
};
const pdf: AttachmentMeta = {
  index: 1,
  filename: "report.pdf",
  content_type: "application/pdf",
  size_bytes: 200000,
};

describe("downloadableAttachments", () => {
  it("excludes inline images referenced by a cid: in the body", () => {
    const html = '<p>hi</p><img src="cid:ii_a@mail">';
    expect(downloadableAttachments([inlineImg, pdf], html)).toEqual([pdf]);
  });

  it("includes an image attachment NOT referenced inline", () => {
    // Same image, but the body never references its content_id → it's a real
    // (downloadable) attachment, not an inline image.
    expect(downloadableAttachments([inlineImg, pdf], "<p>no images</p>")).toEqual([
      inlineImg,
      pdf,
    ]);
  });

  it("treats every attachment as downloadable when there is no HTML body", () => {
    expect(downloadableAttachments([inlineImg, pdf], undefined)).toEqual([
      inlineImg,
      pdf,
    ]);
  });

  it("returns [] for no attachments", () => {
    expect(downloadableAttachments([], "<p>x</p>")).toEqual([]);
    expect(downloadableAttachments(undefined, "<p>x</p>")).toEqual([]);
  });
});

describe("AttachmentChips", () => {
  beforeEach(() => jest.clearAllMocks());

  it("renders a chip per attachment with filename and size", () => {
    render(
      <AttachmentChips email="a@x.dev" messageId="msg_1" attachments={[pdf]} />,
    );
    const chip = screen.getByTestId("attachment-chip");
    expect(chip).toHaveTextContent("report.pdf");
    expect(chip).toHaveTextContent("195 KB");
  });

  it("fetches a download url on click", async () => {
    (getAttachment as jest.Mock).mockResolvedValue({
      download_url: "https://api.e2a.dev/v1/…/download?token=t",
    });
    // jsdom: <a>.click() would navigate; stub it so the click is observable.
    const clickSpy = jest
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {});
    render(
      <AttachmentChips email="a@x.dev" messageId="msg_1" attachments={[pdf]} />,
    );
    fireEvent.click(screen.getByTestId("attachment-chip"));
    await waitFor(() =>
      expect(getAttachment).toHaveBeenCalledWith("a@x.dev", "msg_1", 1),
    );
    expect(clickSpy).toHaveBeenCalled();
    clickSpy.mockRestore();
  });
});
