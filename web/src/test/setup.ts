import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

export class TestEventSource {
  static instances: TestEventSource[] = [];
  readonly listeners = new Map<string, Set<EventListener>>();
  readonly close = vi.fn(() => { this.closed = true; });
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  closed = false;

  constructor(readonly url: string, readonly options?: EventSourceInit) {
    TestEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: EventListener): void {
    const handlers = this.listeners.get(type) || new Set<EventListener>();
    handlers.add(listener);
    this.listeners.set(type, handlers);
  }

  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  emit(type: string, data: string): void {
    for (const listener of this.listeners.get(type) || []) listener(new MessageEvent(type, { data }));
  }

  fail(): void {
    this.onerror?.(new Event("error"));
  }
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.history.replaceState(null, "", "/");
});

beforeEach(() => {
  TestEventSource.instances = [];
  vi.stubGlobal("EventSource", TestEventSource);
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});
