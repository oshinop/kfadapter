import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { ApiError } from "./api";
import { chengduDetails, currentConsumerURL, makeApi, nodes, readyStatus } from "./test/fixtures";
import type { NodeDetails, ProbeResult } from "./types";

async function renderAt(path: string, inventory = nodes) {
  window.history.replaceState(null, "", path);
  const api = makeApi(readyStatus(), inventory);
  render(<App api={api} />);
  await screen.findByRole("heading", { name: "Service status" });
  await waitFor(() => expect(window.location.pathname).toBe("/"));
  return api;
}

async function openGroup(name: string) {
  const group = screen.getByRole("treeitem", { name: `${name} group` });
  expect((group as HTMLDetailsElement).open).toBe(false);
  await userEvent.click(within(group).getByText(name, { exact: true }));
  expect((group as HTMLDetailsElement).open).toBe(true);
  return group;
}

describe("node inventory", () => {
  it("uses canonical status routing and fetches safe SOCKS details only when opened", async () => {
    const api = await renderAt("/nodes");
    expect(screen.getAllByText("Shanghai 01").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Chengdu 02").length).toBeGreaterThan(0);
    expect(screen.queryAllByText("Shanghai Archive")).toHaveLength(0);
    expect(screen.queryByText("203.0.113.20:11001")).toBeNull();
    expect(api.nodeDetails).not.toHaveBeenCalled();
    await openGroup("West China");
    const detailButtons = screen.getAllByRole("button", { name: "Details for Chengdu 02" });
    const probeButtons = screen.getAllByRole("button", { name: "Probe Chengdu 02" });
    expect(detailButtons.length).toBeGreaterThan(0);
    expect(probeButtons.length).toBeGreaterThan(0);
    expect(probeButtons[0].querySelector(".lucide-gauge")).toBeTruthy();

    await userEvent.hover(detailButtons[0]);
    expect(await screen.findByRole("tooltip", { name: "Details" })).toBeTruthy();
    await userEvent.hover(probeButtons[0]);
    expect(await screen.findByRole("tooltip", { name: "Probe latency" })).toBeTruthy();

    await userEvent.click(detailButtons[0]);
    expect(api.nodeDetails).toHaveBeenCalledOnce();
    expect(api.nodeDetails).toHaveBeenCalledWith("n-west");
    expect(await screen.findByRole("heading", { name: "Chengdu 02" })).toBeTruthy();
    expect(screen.getAllByText(chengduDetails.socksAddress).length).toBeGreaterThan(0);
    expect(screen.getByText(chengduDetails.socksUsername)).toBeTruthy();
    expect(screen.getByText(chengduDetails.socksPassword)).toBeTruthy();
    expect(screen.getByText("Latency", { exact: true })).toBeTruthy();
    expect(screen.queryByText("Active TCP", { exact: true })).toBeNull();

    await userEvent.click(detailButtons[0]);
    await waitFor(() => expect(screen.queryByText(chengduDetails.socksPassword)).toBeNull());
  });

  it("uses the accessible probe action and ignores stale details after close or lock", async () => {
    const api = await renderAt("/");
    await openGroup("West China");
    await userEvent.click(screen.getAllByRole("button", { name: "Probe Chengdu 02" })[0]);
    expect(api.probeNode).toHaveBeenCalledWith("n-west");

    const closedDetails = Promise.withResolvers<NodeDetails>();
    const reopenedDetails = Promise.withResolvers<NodeDetails>();
    vi.mocked(api.nodeDetails)
      .mockReturnValueOnce(closedDetails.promise)
      .mockReturnValueOnce(reopenedDetails.promise);
    const detailButton = screen.getAllByRole("button", { name: "Details for Chengdu 02" })[0];
    await userEvent.click(detailButton);
    await userEvent.click(detailButton);
    closedDetails.resolve(chengduDetails);
    await userEvent.click(detailButton);
    expect(await screen.findByText("Loading details")).toBeTruthy();
    expect(screen.queryByText(chengduDetails.socksPassword)).toBeNull();
    await userEvent.click(detailButton);

    const sessionDetails = Promise.withResolvers<NodeDetails>();
    vi.mocked(api.nodeDetails).mockReturnValueOnce(sessionDetails.promise);
    await userEvent.click(detailButton);
    await userEvent.click(screen.getByRole("button", { name: "Lock console" }));
    expect(await screen.findByRole("heading", { name: "Unlock console" })).toBeTruthy();
    sessionDetails.resolve(chengduDetails);
    await waitFor(() => expect(screen.queryByText(chengduDetails.socksPassword)).toBeNull());
    expect(api.clearSession).toHaveBeenCalled();
  });

  it("marks a failed probe as Timeout in the row instead of raising an alert", async () => {
    const api = await renderAt("/");
    vi.mocked(api.probeNode).mockRejectedValueOnce(new ApiError({ title: "Probe failed", status: 502, code: "probe_failed" }));
    await openGroup("West China");
    expect(screen.getByLabelText("Latency 114 ms, Degraded")).toBeTruthy();

    await userEvent.click(screen.getAllByRole("button", { name: "Probe Chengdu 02" })[0]);

    expect(await screen.findByText("Timeout")).toBeTruthy();
    expect(screen.getByLabelText("Latency Timeout, Unhealthy")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();

    await userEvent.click(screen.getAllByRole("button", { name: "Probe Chengdu 02" })[0]);
    expect(await screen.findByLabelText("Latency 84 ms, Healthy")).toBeTruthy();
    expect(screen.queryByText("Timeout")).toBeNull();
  });

  it("prioritizes special groups and sorts China routes and their nodes", async () => {
    await renderAt("/", [
      { ...nodes[0], id: "china-zulu", name: "Zulu 02", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "media", name: "Media 01", group: "音乐/视频APP专线" },
      { ...nodes[1], id: "china-last", name: "Last 01", group: "Zulu ➩ 中国" },
      { ...nodes[0], id: "special", name: "Match 01", group: "2026足球观赛专线" },
      { ...nodes[0], id: "direct", name: "Direct 01", group: "优选直连线路" },
      { ...nodes[1], id: "china-alpha", name: "Alpha 01", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "china-mainland", name: "Mainland 01", group: "港澳台 ➩ 中国大陆" },
    ]);
    const tree = screen.getByRole("tree", { name: "Nodes by group" });
    expect([...tree.children].map((element) => element.getAttribute("aria-label"))).toEqual([
      "2026足球观赛专线 group",
      "优选直连线路 group",
      "音乐/视频APP专线 group",
      "港澳台 ➩ 中国大陆 group",
      "Alpha ➩ 中国 group",
      "Zulu ➩ 中国 group",
    ]);

    const chinaGroup = within(tree).getByRole("treeitem", { name: "Alpha ➩ 中国 group" });
    expect((chinaGroup as HTMLDetailsElement).open).toBe(false);
    await userEvent.click(within(chinaGroup).getByText("Alpha ➩ 中国", { exact: true }));
    expect((chinaGroup as HTMLDetailsElement).open).toBe(true);
    expect(within(chinaGroup).getAllByRole("treeitem").map((element) => element.getAttribute("aria-label"))).toEqual(["Alpha 01", "Zulu 02"]);
    await userEvent.click(within(chinaGroup).getByText("Alpha ➩ 中国", { exact: true }));
    expect((chinaGroup as HTMLDetailsElement).open).toBe(false);
  });

  it("probes sequentially in the same top-down group and node order", async () => {
    const api = await renderAt("/", [
      { ...nodes[0], id: "china-zulu", name: "Zulu 02", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "media", name: "Media 01", group: "音乐/视频APP专线" },
      { ...nodes[1], id: "china-last", name: "Last 01", group: "Zulu ➩ 中国" },
      { ...nodes[0], id: "special", name: "Match 01", group: "2026足球观赛专线" },
      { ...nodes[0], id: "direct", name: "Direct 01", group: "优选直连线路" },
      { ...nodes[1], id: "china-alpha", name: "Alpha 01", group: "Alpha ➩ 中国" },
      { ...nodes[1], id: "china-mainland", name: "Mainland 01", group: "港澳台 ➩ 中国大陆" },
    ]);
    const expectedNodeIDs = ["special", "direct", "media", "china-mainland", "china-alpha", "china-zulu", "china-last"];
    const probes = expectedNodeIDs.map(() => Promise.withResolvers<ProbeResult>());
    let probeIndex = 0;
    vi.mocked(api.probeNode).mockImplementation(() => probes[probeIndex++].promise);
    const probeAll = screen.getByRole("button", { name: "Probe all nodes" }) as HTMLButtonElement;

    await userEvent.click(probeAll);

    for (const [index, nodeId] of expectedNodeIDs.entries()) {
      await waitFor(() => expect(api.probeNode).toHaveBeenCalledTimes(index + 1));
      expect(api.probeNode).toHaveBeenNthCalledWith(index + 1, nodeId);
      probes[index].resolve({ nodeId, health: "healthy", tcpLatencyMs: 40 + index, probedAt: "2026-07-15T10:03:00Z" });
    }
    await waitFor(() => expect(probeAll.disabled).toBe(false));
    expect(api.refresh).not.toHaveBeenCalled();
  });
});

describe("subscription URL", () => {
  it("copies the reusable URL from the canonical status page", async () => {
    await renderAt("/subscription");
    expect(await screen.findByText(currentConsumerURL)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Copy subscription link" }));

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(currentConsumerURL);
    expect(await screen.findByText("Link copied.")).toBeTruthy();
  });
});
