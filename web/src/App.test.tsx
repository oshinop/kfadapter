import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { ApiError } from "./api";
import { currentConsumerURL, makeApi, nodes, readyStatus, signedOutStatus } from "./test/fixtures";

const accessToken = "console-token-12345";

async function openAccountLogin() {
  window.history.replaceState(null, "", "/");
  const api = makeApi(signedOutStatus());
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Connect account" });
  await waitFor(() => expect(window.location.pathname).toBe("/signin"));
  return api;
}

async function openTokenSetup() {
  const api = makeApi(signedOutStatus());
  Object.assign(api, { accessStatus: vi.fn().mockResolvedValue({ initialized: false, authenticated: false }) });
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Create console access" });
  expect(window.location.pathname).toBe("/");
  return api;
}

async function openTokenLogin() {
  const api = makeApi(signedOutStatus());
  Object.assign(api, { accessStatus: vi.fn().mockResolvedValue({ initialized: true, authenticated: false }) });
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Unlock console" });
  expect(window.location.pathname).toBe("/");
  return api;
}

describe("access token and browser session", () => {
  it("creates a first-access token after confirmation, trims it, and clears both fields", async () => {
    const api = await openTokenSetup();
    const historyWrites = vi.spyOn(window.history, "replaceState");
    const token = screen.getByLabelText("Access token") as HTMLInputElement;
    const confirmation = screen.getByLabelText("Confirm access token") as HTMLInputElement;

    await userEvent.type(token, `  ${accessToken}  `);
    await userEvent.type(confirmation, `  ${accessToken}  `);
    await userEvent.click(screen.getByRole("button", { name: "Create access" }));

    expect(api.setupAccess).toHaveBeenCalledWith(accessToken);
    expect(token.value).toBe("");
    expect(confirmation.value).toBe("");
    expect(await screen.findByRole("heading", { name: "Connect account" })).toBeTruthy();
    expect(JSON.stringify(historyWrites.mock.calls)).not.toContain(accessToken);
  });

  it("validates token byte guidance and matching confirmation before setup", async () => {
    const api = await openTokenSetup();
    await userEvent.type(screen.getByLabelText("Access token"), "too-short");
    await userEvent.type(screen.getByLabelText("Confirm access token"), "too-short");
    await userEvent.click(screen.getByRole("button", { name: "Create access" }));
    expect(api.setupAccess).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toMatch(/too short or too long/i);

    await userEvent.type(screen.getByLabelText("Access token"), accessToken);
    await userEvent.type(screen.getByLabelText("Confirm access token"), "different-token-12345");
    await userEvent.click(screen.getByRole("button", { name: "Create access" }));
    expect(api.setupAccess).not.toHaveBeenCalled();
    expect(await screen.findByText(/access tokens do not match/i)).toBeTruthy();
  });

  it("submits a returning token and clears it before a blocked request settles", async () => {
    const api = await openTokenLogin();
    const pendingLogin = Promise.withResolvers<void>();
    Object.assign(api, { loginAccess: vi.fn().mockReturnValue(pendingLogin.promise) });
    const token = screen.getByLabelText("Access token") as HTMLInputElement;
    await userEvent.type(token, accessToken);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(api.loginAccess).toHaveBeenCalledWith(accessToken);
    expect(token.value).toBe("");
  });

  it("keeps a rejected returning-token field empty", async () => {
    const api = await openTokenLogin();
    Object.assign(api, { loginAccess: vi.fn().mockRejectedValue(new ApiError({ title: "Rejected", status: 401, code: "invalid_access_token" })) });
    const token = screen.getByLabelText("Access token") as HTMLInputElement;
    await userEvent.type(token, accessToken);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByText("That access token was not accepted.")).toBeTruthy();
    expect(token.value).toBe("");
  });

  it("signs into the existing account at the provider route and clears the account password", async () => {
    const api = await openAccountLogin();
    const historyWrites = vi.spyOn(window.history, "replaceState");
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(password, "do-not-retain");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByRole("heading", { name: "Service status" });
    expect(window.location.pathname).toBe("/");
    expect(password.value).toBe("");
    expect(api.login).toHaveBeenCalledWith("operator@example.com", "do-not-retain");
    expect(JSON.stringify(historyWrites.mock.calls)).not.toContain("do-not-retain");
  });

  it("shows an invalid account error and clears its password", async () => {
    const api = await openAccountLogin();
    Object.assign(api, { login: vi.fn().mockRejectedValue(new ApiError({ title: "Unauthorized", status: 401, code: "login_rejected" })) });
    const password = screen.getByLabelText("Password") as HTMLInputElement;
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(password, "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("The provider rejected that email or password.")).toBeTruthy();
    expect(password.value).toBe("");
  });

  it("uses only the button spinner while account sign-in is pending", async () => {
    const api = await openAccountLogin();
    const pending = Promise.withResolvers<void>();
    Object.assign(api, { login: vi.fn().mockReturnValue(pending.promise) });
    await userEvent.type(screen.getByLabelText("Email"), "operator@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));

    expect((screen.getByRole("button", { name: "Signing in" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText("Signing in to your account…")).toBeNull();
  });

  it("signs out the provider account and locks the console", async () => {
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Sign out account" }));

    expect(await screen.findByRole("heading", { name: "Unlock console" })).toBeTruthy();
    expect(window.location.pathname).toBe("/");
    expect(screen.queryByText(currentConsumerURL)).toBeNull();
    expect(api.logoutAccount).toHaveBeenCalledOnce();
    expect(api.lockConsole).toHaveBeenCalledOnce();
    expect(api.clearSession).toHaveBeenCalledOnce();
  });

  it("locks the console separately and returns to the canonical route after unlock", async () => {
    window.history.replaceState(null, "", "/signin");
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    expect(window.location.pathname).toBe("/");

    await userEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(await screen.findByRole("heading", { name: "Unlock console" })).toBeTruthy();
    expect(window.location.pathname).toBe("/");
    expect(api.lockConsole).toHaveBeenCalledOnce();
    expect(api.logoutAccount).not.toHaveBeenCalled();

    await userEvent.type(screen.getByLabelText("Access token"), accessToken);
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { name: "Service status" })).toBeTruthy();
    expect(window.location.pathname).toBe("/");
  });

  it("refreshes account and node-list data from the page header without adding a success hint", async () => {
    const api = makeApi(readyStatus());
    const refreshedNodes = [{ ...nodes[0], name: "Beijing 01" }, nodes[1]];
    vi.mocked(api.nodes)
      .mockResolvedValueOnce({ nodes })
      .mockResolvedValueOnce({ nodes: refreshedNodes });
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    const refreshButton = screen.getByRole("button", { name: "Refresh account and node list" });
    expect(refreshButton.closest('[data-slot="card"]')).toBeNull();
    expect(refreshButton.querySelector(".lucide-refresh-cw")).toBeTruthy();

    await userEvent.click(refreshButton);

    await waitFor(() => expect(api.refresh).toHaveBeenCalledOnce());
    await waitFor(() => expect(api.status).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(api.nodes).toHaveBeenCalledTimes(2));
    await userEvent.click(screen.getByText("East China", { exact: true }));
    expect(await screen.findByRole("treeitem", { name: "Beijing 01" })).toBeTruthy();
    expect(screen.queryByText(/(?:account|nodes) (?:refreshed|updated)/i)).toBeNull();
  });

  it("renders every logical catalog row supplied by the backend", async () => {
    const music = Array.from({ length: 5 }, (_, index) => ({
      ...nodes[0],
      id: `music-${index + 1}`,
      name: `音乐/视频专线 · ${index + 1}`,
      group: "音乐/视频APP专线",
    }));
    const catalogNodes: typeof nodes = [
      ...music,
      { ...nodes[0], id: "australia-2", name: "澳大利亚 ➩ 中国 · 2", group: "澳洲 ➩ 中国" },
      { ...nodes[0], id: "australia-7", name: "澳大利亚 ➩ 中国 · 7", group: "澳洲 ➩ 中国" },
    ];
    const status = readyStatus();
    status.nodes = { total: catalogNodes.length, eligible: catalogNodes.length, healthy: catalogNodes.length };
    status.subscription.nodeCount = catalogNodes.length;
    render(<App api={makeApi(status, catalogNodes)} />);

    expect(await screen.findByText("7 available")).toBeTruthy();
    const musicGroup = screen.getByLabelText("音乐/视频APP专线 group");
    expect(musicGroup.textContent).toContain("5");
    await userEvent.click(screen.getByText("音乐/视频APP专线", { exact: true }));
    for (const node of music) expect(screen.getByRole("treeitem", { name: node.name })).toBeTruthy();

    const australiaGroup = screen.getByLabelText("澳洲 ➩ 中国 group");
    expect(australiaGroup.textContent).toContain("2");
    await userEvent.click(screen.getByText("澳洲 ➩ 中国", { exact: true }));
    expect(screen.getByRole("treeitem", { name: "澳大利亚 ➩ 中国 · 2" })).toBeTruthy();
    expect(screen.getByRole("treeitem", { name: "澳大利亚 ➩ 中国 · 7" })).toBeTruthy();
  });

  it.each([
    ["authenticating", "Authenticating"],
    ["syncing", "Syncing"],
    ["ready", "Ready"],
    ["degraded", "Needs attention"],
    ["error", "Service error"],
  ] as const)("renders the %s service state with text, not color alone", async (state, expected) => {
    const api = makeApi({ ...readyStatus(), state });
    render(<App api={api} />);
    expect((await screen.findAllByText(expected, { exact: true })).length).toBeGreaterThan(0);
  });

  it("omits redundant ready-state and connection-counter status", async () => {
    render(<App api={makeApi(readyStatus())} />);
    await screen.findByRole("heading", { name: "Service status" });
    expect(screen.queryByText("Service is ready.", { exact: true })).toBeNull();
    expect(screen.queryByText("Legacy tunnel", { exact: true })).toBeNull();
    expect(screen.queryByText("Connections", { exact: true })).toBeNull();
  });

  it("avoids browser storage while rendering the status console", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const api = makeApi(readyStatus());
    render(<App api={api} />);
    await screen.findByRole("heading", { name: "Service status" });
    await waitFor(() => expect(api.accessStatus).toHaveBeenCalled());
    expect(setItem).not.toHaveBeenCalled();
    expect(window.location.search).toBe("");
    expect(window.location.hash).toBe("");
  });
});
