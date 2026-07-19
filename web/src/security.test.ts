import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { ApiClient } from "./api";
import { currentConsumerURL } from "./test/fixtures";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("browser boundary", () => {
  it("uses same-origin API paths with credentials and never writes browser storage", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ initialized: true, authenticated: true, csrfToken: "csrf-test" }))
      .mockResolvedValueOnce(jsonResponse({ csrfToken: "csrf-test" }))
      .mockResolvedValueOnce(jsonResponse({ csrfToken: "csrf-test" }))
      .mockResolvedValueOnce(jsonResponse({ state: "ready" }))
      .mockResolvedValueOnce(jsonResponse({}));
    vi.stubGlobal("fetch", fetchMock);
    const storageWrite = vi.spyOn(Storage.prototype, "setItem");
    const api = new ApiClient();

    await api.accessStatus();
    await api.setupAccess("console-token-12345");
    await api.loginAccess("console-token-12345");
    await api.status();
    await api.login("operator@example.com", "volatile-password");

    for (const [request, options] of fetchMock.mock.calls) {
      expect(request).toMatch(/^\/api\/v1\//);
      expect(options.credentials).toBe("same-origin");
      expect(options.cache).toBe("no-store");
    }
    expect(fetchMock.mock.calls.map(([request]) => request)).toEqual([
      "/api/v1/access/status",
      "/api/v1/access/setup",
      "/api/v1/access/login",
      "/api/v1/status",
      "/api/v1/auth/login",
    ]);
    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBeUndefined();
    expect(fetchMock.mock.calls[2][1].headers["X-CSRF-Token"]).toBeUndefined();
    expect(fetchMock.mock.calls[4][1].headers["X-CSRF-Token"]).toBe("csrf-test");
    expect(storageWrite).not.toHaveBeenCalled();
  });

  it("clears CSRF after an HTTP console-lock response", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ title: "Unavailable", status: 503, code: "temporary" }), { status: 503, headers: { "Content-Type": "application/problem+json" } }))
      .mockResolvedValueOnce(jsonResponse({ state: "signed_out" }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new ApiClient();
    api.setCsrfToken("csrf-before-logout");

    await expect(api.lockConsole()).rejects.toBeInstanceOf(Error);
    await api.refresh();

    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/access/logout");
  });

  it("treats an unauthorized lock response as an already locked console", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ title: "Authentication required", status: 401, code: "not_authenticated" }), { status: 401, headers: { "Content-Type": "application/problem+json" } }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new ApiClient();
    api.setCsrfToken("csrf-before-lock");

    await expect(api.lockConsole()).resolves.toBeUndefined();
    await api.refresh();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/access/logout");
    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("");
  });

  it("retains CSRF for retry after a transport-level console-lock failure", async () => {
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(new TypeError("Network unavailable"))
      .mockResolvedValueOnce(jsonResponse({}))
      .mockResolvedValueOnce(jsonResponse({ state: "signed_out" }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new ApiClient();
    api.setCsrfToken("csrf-retry-token");

    await expect(api.lockConsole()).rejects.toBeInstanceOf(TypeError);
    await api.lockConsole();
    await api.refresh();

    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("csrf-retry-token");
    expect(fetchMock.mock.calls[2][1].headers["X-CSRF-Token"]).toBe("");
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/access/logout");
  });

  it("loads the reusable subscription URL through its authenticated GET endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ url: currentConsumerURL, generation: 7 }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new ApiClient();
    api.setCsrfToken("csrf-test");

    await expect(api.subscriptionURL()).resolves.toEqual({ url: currentConsumerURL, generation: 7 });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/subscription/url");
    expect(fetchMock.mock.calls[0][1].method).toBe("GET");
  });

  it("ships a CSP-compatible self-hosted production shell with no remote asset URL", () => {
    const staticDirectory = resolve(process.cwd(), "../internal/web/static");
    const index = readFileSync(`${staticDirectory}/index.html`, "utf8");
    const assetNames = readdirSync(`${staticDirectory}/assets`);
    const mainBundles = assetNames.filter((file) => /^index-[A-Za-z0-9_-]+\.js$/.test(file));
    const stylesheets = assetNames.filter((file) => /^style-[A-Za-z0-9_-]+\.css$/.test(file));
    const assetContent = assetNames
      .filter((file) => file.endsWith(".css") || file.endsWith(".js"))
      .map((file) => readFileSync(`${staticDirectory}/assets/${file}`, "utf8"))
      .join("\n");

    expect(mainBundles).toHaveLength(1);
    expect(stylesheets).toHaveLength(1);
    expect(index).toContain(`/assets/${mainBundles[0]}`);
    expect(index).toContain(`/assets/${stylesheets[0]}`);
    expect(index).toMatch(/<script[^>]+type="module"[^>]+src="\/assets\//);
    expect(index).not.toMatch(/<script(?![^>]+src=)/);
    expect(index).not.toMatch(/style=/i);
    const resourceURLs = [
      ...[...index.matchAll(/(?:src|href)=["']?([^"'\s>]+)/gi)].map((match) => match[1]),
      ...[...assetContent.matchAll(/url\(["']?([^"')\s]+)/gi)].map((match) => match[1]),
    ];
    expect(resourceURLs.every((url) => !/^https?:/i.test(url))).toBe(true);
    expect(`${index}\n${assetContent}`).not.toMatch(/localStorage|sessionStorage/);
  });
});
