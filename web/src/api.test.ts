import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./api";

const jsonHeaders = { "Content-Type": "application/json" };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("API response contracts", () => {
  it("strips endpoint and exclusion fields from node list responses", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      nodes: [{
        id: "node-1",
        name: "Node 01",
        group: "Test group",
        provider: "Test provider",
        endpoint: "203.0.113.10:11000",
        excluded: true,
        health: "healthy",
        tcpLatencyMs: 42,
        udpHealth: "unavailable",
        eligible: true,
      }],
    }), { status: 200, headers: jsonHeaders }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await new ApiClient().nodes();

    expect(result.nodes[0]).toMatchObject({
      id: "node-1",
      name: "Node 01",
      health: "healthy",
      tcpLatencyMs: 42,
    });
    expect(result.nodes[0]).not.toHaveProperty("endpoint");
    expect(result.nodes[0]).not.toHaveProperty("excluded");
  });

  it("loads URL-encoded node details with a no-store request", async () => {
    const details = {
      id: "node / 1",
      name: "Node 01",
      group: "Test group",
      provider: "Test provider",
      upstreamHost: "127.0.0.1",
      upstreamPort: 10808,
      socksAddress: "127.0.0.1:10808",
      socksUsername: "local-user",
      socksPassword: "local-password",
      health: "healthy",
      tcpLatencyMs: 42,
      generation: 7,
    };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(details), { status: 200, headers: jsonHeaders }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(new ApiClient().nodeDetails("node / 1")).resolves.toEqual(details);

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/nodes/node%20%2F%201/details");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: "GET", credentials: "same-origin", cache: "no-store" });
  });

  it("keeps account logout separate from the console lock and clears CSRF only after locking", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }));
    vi.stubGlobal("fetch", fetchMock);
    const api = new ApiClient();
    api.setCsrfToken("csrf-before-logout");

    await expect(api.logoutAccount()).resolves.toBeUndefined();
    await api.refresh();
    await expect(api.lockConsole()).resolves.toBeUndefined();
    await api.refresh();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/auth/logout");
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ method: "POST", credentials: "same-origin", cache: "no-store" });
    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("csrf-before-logout");
    expect(fetchMock.mock.calls[2][0]).toBe("/api/v1/access/logout");
    expect(fetchMock.mock.calls[2][1].method).toBe("POST");
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({});
    expect(fetchMock.mock.calls[3][1].headers["X-CSRF-Token"]).toBe("");
  });

  it("accepts the empty 202 refresh acknowledgement", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(new ApiClient().refresh()).resolves.toBeUndefined();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/control/refresh");
    expect(fetchMock.mock.calls[0][1].method).toBe("POST");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({});
  });
});
