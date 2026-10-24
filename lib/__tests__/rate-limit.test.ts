import { afterEach, describe, it, expect, beforeEach, vi } from "vitest";
import { NextRequest } from "next/server";

const redisMocks = vi.hoisted(() => {
  const client = {
    isOpen: true,
    connect: vi.fn().mockResolvedValue(undefined),
    eval: vi.fn(),
    on: vi.fn(),
  };
  return { client, createClient: vi.fn(() => client) };
});

vi.mock("@redis/client", () => ({
  createClient: redisMocks.createClient,
}));

import {
  checkRateLimit,
  getClientIdentifier,
  createRateLimitResponse,
  enforceRateLimit,
  resetRateLimitStoreForTesting,
  RateLimitConfig,
} from "@/lib/rate-limit";

describe("Rate Limiting Engine", () => {
  beforeEach(() => {
    resetRateLimitStoreForTesting();
    vi.stubEnv("REDIS_URL", "");
    redisMocks.client.eval.mockReset();
    redisMocks.client.connect.mockClear();
    redisMocks.client.on.mockClear();
    redisMocks.createClient.mockClear();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("permits requests within configured window and threshold", async () => {
    const config: RateLimitConfig = {
      maxRequests: 3,
      windowMs: 10_000,
      name: "test-allow",
    };

    const res1 = await checkRateLimit("client-1", config);
    expect(res1.success).toBe(true);
    expect(res1.remaining).toBe(2);

    const res2 = await checkRateLimit("client-1", config);
    expect(res2.success).toBe(true);
    expect(res2.remaining).toBe(1);

    const res3 = await checkRateLimit("client-1", config);
    expect(res3.success).toBe(true);
    expect(res3.remaining).toBe(0);
  });

  it("blocks requests once rate limit is exceeded", async () => {
    const config: RateLimitConfig = {
      maxRequests: 2,
      windowMs: 5_000,
      blockDurationMs: 8_000,
      name: "test-block",
    };

    await checkRateLimit("client-2", config);
    await checkRateLimit("client-2", config);

    // Third request exceeds limit
    const blockedRes = await checkRateLimit("client-2", config);
    expect(blockedRes.success).toBe(false);
    expect(blockedRes.remaining).toBe(0);
    expect(blockedRes.retryAfterMs).toBeGreaterThan(0);
    expect(blockedRes.retryAfterMs).toBeLessThanOrEqual(8000);
  });

  it("isolates different client identifiers", async () => {
    const config: RateLimitConfig = {
      maxRequests: 1,
      windowMs: 5_000,
      name: "test-isolation",
    };

    const clientA = await checkRateLimit("192.168.1.1", config);
    expect(clientA.success).toBe(true);

    const clientASecond = await checkRateLimit("192.168.1.1", config);
    expect(clientASecond.success).toBe(false);

    // Client B should still succeed
    const clientB = await checkRateLimit("192.168.1.2", config);
    expect(clientB.success).toBe(true);
  });

  it("correctly parses client identifier from proxy and ip headers", () => {
    const headers1 = new Headers({ "x-forwarded-for": "203.0.113.195, 70.41.3.18" });
    expect(getClientIdentifier(headers1)).toBe("203.0.113.195");

    const headers2 = new Headers({ "x-real-ip": "198.51.100.4" });
    expect(getClientIdentifier(headers2)).toBe("198.51.100.4");

    const headers3 = new Headers({});
    expect(getClientIdentifier(headers3)).toBe("anonymous");
  });

  it("constructs standard 429 response with proper headers", async () => {
    const limit = {
      success: false,
      remaining: 0,
      resetMs: 15_000,
      retryAfterMs: 15_000,
    };

    const res = createRateLimitResponse(limit, "Custom rate limit error");
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("15");
    expect(res.headers.get("X-RateLimit-Remaining")).toBe("0");

    const data = await res.json();
    expect(data.error).toBe("Custom rate limit error");
    expect(data.isError).toBe(true);
    expect(data.retryAfterMs).toBe(15_000);
  });

  it("uses an atomic Redis sliding window without storing raw client identifiers", async () => {
    vi.stubEnv("REDIS_URL", "rediss://redis.example.test");
    redisMocks.client.eval.mockResolvedValueOnce([1, 2, 45_000]);

    const result = await checkRateLimit("client-secret-ip", {
      maxRequests: 3,
      windowMs: 60_000,
      name: "test-redis",
    });

    expect(result).toEqual({
      success: true,
      remaining: 2,
      resetMs: 45_000,
      retryAfterMs: undefined,
    });
    expect(redisMocks.createClient).toHaveBeenCalledOnce();
    expect(redisMocks.client.eval).toHaveBeenCalledOnce();

    const [script, options] = redisMocks.client.eval.mock.calls[0];
    expect(script).toContain("ZREMRANGEBYSCORE");
    expect(script).toContain("ZADD");
    expect(options.keys[0]).not.toContain("client-secret-ip");
    expect(options.keys[0]).toContain("{");
    expect(options.keys[0].split("{")[1].split("}")[0]).toBe(
      options.keys[1].split("{")[1].split("}")[0]
    );
  });

  it("returns 503 and logs when the shared Redis limiter is unavailable", async () => {
    vi.stubEnv("REDIS_URL", "rediss://redis.example.test");
    redisMocks.client.eval.mockRejectedValueOnce(new Error("Redis unavailable"));
    vi.spyOn(console, "error").mockImplementation(() => {});

    const guard = await enforceRateLimit(
      new NextRequest("http://localhost/api/test"),
      {
        maxRequests: 1,
        windowMs: 1_000,
        name: "test-redis-outage",
      }
    );

    expect(guard.success).toBe(false);
    if (guard.success) throw new Error("Expected rate limiting to fail closed.");
    expect(guard.response.status).toBe(503);
    await expect(guard.response.json()).resolves.toMatchObject({
      error: "Request protection is temporarily unavailable.",
    });
    expect(console.error).toHaveBeenCalledOnce();
  });

  it("falls back to in-memory limiting in production when Redis is not configured", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("REDIS_URL", "");
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const config: RateLimitConfig = {
      maxRequests: 1,
      windowMs: 1_000,
      name: "test-production-config",
    };
    const request = new NextRequest("http://localhost/api/test");

    const first = await enforceRateLimit(request, config);
    expect(first.success).toBe(true);
    expect(redisMocks.createClient).not.toHaveBeenCalled();

    const second = await enforceRateLimit(request, config);
    expect(second.success).toBe(false);
    if (second.success) throw new Error("Expected second request to be limited.");
    expect(second.response.status).toBe(429);
  });
});
