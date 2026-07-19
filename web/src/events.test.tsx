import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { currentConsumerURL, nodes, readyStatus } from "./test/fixtures";
import { TestEventSource } from "./test/setup";
import type { NodeRecord, StatusResponse } from "./types";

function response(payload: unknown, status = 200) {
  return new Response(status === 204 ? null : JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderAuthenticatedConsole(pathname = "/") {
  let currentStatus: StatusResponse = readyStatus();
  let currentNodes: NodeRecord[] = nodes;
  let statusFailure: number | null = null;
  const fetchMock = vi.fn((resource: RequestInfo | URL, init?: RequestInit) => {
    const path = typeof resource === "string" ? resource : resource.toString();
    if (path.endsWith("/access/status")) return Promise.resolve(response({ initialized: true, authenticated: true, csrfToken: "csrf-test" }));
    if (path.endsWith("/status")) {
      if (statusFailure) return Promise.resolve(response({ title: "Session check failed", status: statusFailure, code: "session_check_failed" }, statusFailure));
      return Promise.resolve(response(currentStatus));
    }
    if (path.endsWith("/nodes")) return Promise.resolve(response({ nodes: currentNodes }));
    if (path.endsWith("/subscription/url")) return Promise.resolve(response({ url: currentConsumerURL, generation: 7 }));
    if (path === "/api/v1/access/logout" && init?.method === "POST") return Promise.resolve(response(null, 204));
    throw new Error(`Unexpected request: ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  window.history.replaceState(null, "", pathname);
  const eventSourceIndex = TestEventSource.instances.length;
  const result = render(<App />);
  return {
    ...result,
    fetchMock,
    eventSource: () => TestEventSource.instances[eventSourceIndex],
    setStatus: (status: StatusResponse) => { currentStatus = status; },
    setNodes: (nextNodes: NodeRecord[]) => { currentNodes = nextNodes; },
    setStatusFailure: (status: number | null) => { statusFailure = status; },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("named server-sent events", () => {

  it("coalesces named state, refresh, and probe events into one authoritative reload", async () => {
    const console = renderAuthenticatedConsole();
    await screen.findByRole("heading", { name: "Service status" });
    await waitFor(() => expect(console.eventSource()).toBeTruthy());
    await waitFor(() => expect(console.fetchMock.mock.calls.filter(([request]) => String(request).endsWith("/subscription/url")).length).toBe(1));
    const baselineCalls = console.fetchMock.mock.calls.length;
    const updated = { ...readyStatus(), state: "degraded" as const };
    console.setStatus(updated);
    console.setNodes([{ ...nodes[0], health: "degraded" }]);
    const source = console.eventSource();

    await act(async () => {
      source.emit("state", JSON.stringify({ state: "degraded", generation: 8 }));
      source.emit("refresh", JSON.stringify({ state: "degraded", generation: 8, complete: true }));
      source.emit("probe", JSON.stringify({ nodeId: "n-east", health: "degraded", tcpLatencyMs: 84, probedAt: "2026-07-15T10:00:00Z" }));
    });

    expect(await screen.findByText("Needs attention", { exact: true })).toBeTruthy();
    await waitFor(() => expect(console.fetchMock.mock.calls.length).toBe(baselineCalls + 3));
  });

  it("clears the stable subscription URL when a named stream error reconciles to 401", async () => {
    const console = renderAuthenticatedConsole("/subscription");
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();
    await waitFor(() => expect(console.eventSource()).toBeTruthy());
    const source = console.eventSource();
    console.setStatusFailure(401);

    source.fail();

    expect(await screen.findByRole("heading", { name: "Unlock console" })).toBeTruthy();
    expect(window.location.pathname).toBe("/");
    expect(screen.queryByText(currentConsumerURL)).toBeNull();
    await waitFor(() => expect(source.close).toHaveBeenCalledOnce());
  });

  it("retains data after transient stream reconciliation failure and bounds error bursts", async () => {
    const console = renderAuthenticatedConsole();
    await screen.findByRole("heading", { name: "Service status" });
    await waitFor(() => expect(console.eventSource()).toBeTruthy());
    await waitFor(() => expect(console.fetchMock.mock.calls.filter(([request]) => String(request).endsWith("/subscription/url")).length).toBe(1));
    const baselineCalls = console.fetchMock.mock.calls.length;
    const source = console.eventSource();
    console.setStatusFailure(503);

    source.fail();
    source.fail();
    source.fail();

    expect((await screen.findAllByText("Ready", { exact: true })).length).toBeGreaterThan(0);
    expect(await screen.findByText("Session check failed")).toBeTruthy();
    await waitFor(() => expect(console.fetchMock.mock.calls.length).toBe(baselineCalls + 1));
  });

  it("closes named listeners when the console locks and when it unmounts", async () => {
    const logoutConsole = renderAuthenticatedConsole();
    await screen.findByRole("heading", { name: "Service status" });
    await waitFor(() => expect(logoutConsole.eventSource()).toBeTruthy());
    const logoutSource = logoutConsole.eventSource();
    await userEvent.click(screen.getByRole("button", { name: "Lock console" }));
    await screen.findByRole("heading", { name: "Unlock console" });
    await waitFor(() => expect(logoutSource.close).toHaveBeenCalledOnce());
    expect([...logoutSource.listeners.values()].every((listeners) => listeners.size === 0)).toBe(true);
    logoutConsole.unmount();

    const unmountConsole = renderAuthenticatedConsole();
    await screen.findByRole("heading", { name: "Service status" });
    await waitFor(() => expect(unmountConsole.eventSource()).toBeTruthy());
    const unmountSource = unmountConsole.eventSource();
    unmountConsole.unmount();
    expect(unmountSource.close).toHaveBeenCalledOnce();
    expect([...unmountSource.listeners.values()].every((listeners) => listeners.size === 0)).toBe(true);
  });
});
