import { afterEach, describe, expect, it, vi } from "vitest";
import { TerminalOutputBatcher, type TerminalOutputBatch } from "../src/main/app/terminal-output-batcher.js";
import type { TerminalLine } from "../src/shared/types.js";

describe("TerminalOutputBatcher", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("coalesces adjacent output and flushes it at a bounded cadence", () => {
    vi.useFakeTimers();
    const batches: Array<TerminalOutputBatch<"ssh">> = [];
    const batcher = new TerminalOutputBatcher<"ssh">((batch) => batches.push(batch), { flushDelayMs: 20 });

    batcher.enqueue("ssh", line("one", "stdout", "a"));
    batcher.enqueue("ssh", line("two", "stdout", "b"));
    expect(batches).toEqual([]);

    vi.advanceTimersByTime(20);
    expect(batches).toHaveLength(1);
    expect(batches[0]?.lines).toEqual([line("one", "stdout", "ab")]);
  });

  it("materializes a noisy terminal segment only when it is flushed", () => {
    vi.useFakeTimers();
    const batches: Array<TerminalOutputBatch<"ssh">> = [];
    const batcher = new TerminalOutputBatcher<"ssh">((batch) => batches.push(batch), {
      flushDelayMs: 20,
      maxPendingBytes: 1024 * 1024
    });

    for (let index = 0; index < 1000; index += 1) {
      batcher.enqueue("ssh", line(String(index), "stdout", "x"));
    }

    expect(batches).toEqual([]);
    vi.advanceTimersByTime(20);
    expect(batches[0]?.lines).toHaveLength(1);
    expect(batches[0]?.lines[0]?.text).toBe("x".repeat(1000));
  });

  it("ignores empty chunks instead of retaining unbounded segment metadata", () => {
    vi.useFakeTimers();
    const batches: Array<TerminalOutputBatch<"ssh">> = [];
    const batcher = new TerminalOutputBatcher<"ssh">((batch) => batches.push(batch));

    for (let index = 0; index < 10_000; index += 1) {
      batcher.enqueue("ssh", line(String(index), "stdout", ""));
    }
    vi.runAllTimers();

    expect(batches).toEqual([]);
  });

  it("bounds pending bytes and segments while reporting dropped output", () => {
    vi.useFakeTimers();
    const batches: Array<TerminalOutputBatch<"ssh">> = [];
    const batcher = new TerminalOutputBatcher<"ssh">((batch) => batches.push(batch), {
      flushDelayMs: 10,
      maxPendingBytes: 4,
      maxSegments: 2
    });

    batcher.enqueue("ssh", line("one", "stdout", "abcd"));
    batcher.enqueue("ssh", line("two", "stderr", "x"));
    batcher.enqueue("ssh", line("three", "stdout", "yz"));
    vi.advanceTimersByTime(10);

    expect(batches[0]?.lines.map((entry) => entry.text)).toEqual(["abcd"]);
    expect(batches[0]?.droppedBytes).toBe(3);
  });

  it("flushes lifecycle messages in order and can discard stale transport output", () => {
    vi.useFakeTimers();
    const batches: Array<TerminalOutputBatch<"ssh">> = [];
    const batcher = new TerminalOutputBatcher<"ssh">((batch) => batches.push(batch));
    batcher.enqueue("ssh", line("one", "stdout", "prompt"));
    batcher.enqueue("ssh", line("close", "system", "closed"));

    expect(batches.map((batch) => batch.lines.map((entry) => entry.text))).toEqual([["prompt"], ["closed"]]);

    batcher.enqueue("ssh", line("stale", "stdout", "stale"));
    batcher.clear();
    vi.runAllTimers();
    expect(batches).toHaveLength(2);
  });
});

function line(id: string, stream: TerminalLine["stream"], text: string): TerminalLine {
  return { id, at: "2026-01-01T00:00:00.000Z", stream, text };
}
