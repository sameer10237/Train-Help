import { createHash, randomUUID } from "node:crypto";
import { createClient } from "@redis/client";
import { NextRequest, NextResponse } from "next/server";

export interface RateLimitEntry {
  timestamps: number[];
  blockedUntil: number | null;
}

export interface RateLimitConfig {
  /** Maximum requests allowed within the window */
  maxRequests: number;
  /** Time window in milliseconds */
  windowMs: number;
  /** Optional: block duration in ms after limit is exceeded (default: windowMs) */
  blockDurationMs?: number;
  /** Identifier for this limiter */
  name?: string;
}

export interface RateLimitResult {
  success: boolean;
  remaining: number;
  resetMs: number;
  retryAfterMs?: number;
}

type RedisClient = ReturnType<typeof createClient>;

type EnforcedRateLimit =
  | { success: true; limit: RateLimitResult }
  | { success: false; response: NextResponse };

const stores = new Map<string, Map<string, RateLimitEntry>>();

let cleanupScheduled = false;
let warnedAboutMemoryFallback = false;
let redisClient: RedisClient | null = null;
let redisConnection: Promise<RedisClient> | null = null;

const REDIS_RATE_LIMIT_SCRIPT = `
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local block_duration = tonumber(ARGV[4])
local member = ARGV[5]

local blocked_until = tonumber(redis.call("GET", KEYS[2]))
if blocked_until and now < blocked_until then
  return {0, 0, blocked_until - now}
end
if blocked_until then
  redis.call("DEL", KEYS[2])
end

redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now - window)
local count = redis.call("ZCARD", KEYS[1])
if count >= max_requests then
  redis.call("SET", KEYS[2], now + block_duration, "PX", block_duration)
  return {0, 0, block_duration}
end

redis.call("ZADD", KEYS[1], now, member)
redis.call("PEXPIRE", KEYS[1], math.max(window, block_duration))

local oldest = redis.call("ZRANGE", KEYS[1], 0, 0, "WITHSCORES")
local reset = window
if #oldest >= 2 then
  reset = math.max(0, window - (now - tonumber(oldest[2])))
end

return {1, max_requests - count - 1, reset}
`;

function getStore(name: string): Map<string, RateLimitEntry> {
  let store = stores.get(name);
  if (!store) {
    store = new Map();
    stores.set(name, store);
  }
  return store;
}

function scheduleCleanup() {
  if (cleanupScheduled) return;
  cleanupScheduled = true;

  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const store of stores.values()) {
      for (const [key, entry] of store) {
        const freshTimestamps = entry.timestamps.filter(
          (timestamp) => now - timestamp < 300_000
        );
        if (
          freshTimestamps.length === 0 &&
          (!entry.blockedUntil || entry.blockedUntil < now)
        ) {
          store.delete(key);
        } else {
          entry.timestamps = freshTimestamps;
        }
      }
    }
  }, 60_000);
  cleanupInterval.unref();
}

function checkInMemoryRateLimit(
  identifier: string,
  config: RateLimitConfig
): RateLimitResult {
  const {
    maxRequests,
    windowMs,
    blockDurationMs = windowMs,
    name = "default",
  } = config;

  scheduleCleanup();
  const store = getStore(name);
  const now = Date.now();

  let entry = store.get(identifier);
  if (!entry) {
    entry = { timestamps: [], blockedUntil: null };
    store.set(identifier, entry);
  }

  if (entry.blockedUntil && now < entry.blockedUntil) {
    const retryAfterMs = entry.blockedUntil - now;
    return { success: false, remaining: 0, resetMs: retryAfterMs, retryAfterMs };
  }

  if (entry.blockedUntil && now >= entry.blockedUntil) {
    entry.blockedUntil = null;
    entry.timestamps = [];
  }

  entry.timestamps = entry.timestamps.filter(
    (timestamp) => now - timestamp < windowMs
  );

  if (entry.timestamps.length >= maxRequests) {
    entry.blockedUntil = now + blockDurationMs;
    return {
      success: false,
      remaining: 0,
      resetMs: blockDurationMs,
      retryAfterMs: blockDurationMs,
    };
  }

  entry.timestamps.push(now);
  const remaining = maxRequests - entry.timestamps.length;
  const oldestInWindow = entry.timestamps[0] ?? now;
  const resetMs = windowMs - (now - oldestInWindow);

  return { success: true, remaining, resetMs };
}

async function getRedisClient(): Promise<RedisClient> {
  const url = process.env.REDIS_URL;
  if (!url) {
    throw new Error("REDIS_URL is required for shared rate limiting.");
  }

  if (!redisClient) {
    redisClient = createClient({ url });
    redisClient.on("error", (error) => {
      console.error("Redis rate limiter client error:", error);
    });
    redisClient.on("end", () => {
      redisClient = null;
      redisConnection = null;
    });
  }

  if (redisClient.isOpen) return redisClient;

  if (!redisConnection) {
    const client = redisClient;
    redisConnection = client.connect().then(
      () => client,
      (error: unknown) => {
        if (redisClient === client) {
          redisClient = null;
          redisConnection = null;
        }
        throw error;
      }
    );
  }

  return redisConnection;
}

async function checkRedisRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  const {
    maxRequests,
    windowMs,
    blockDurationMs = windowMs,
    name = "default",
  } = config;

  const client = await getRedisClient();
  const identifierHash = createHash("sha256")
    .update(`${name}:${identifier}`)
    .digest("hex");
  const keyPrefix = `travel-rescue:rate-limit:${name}:{${identifierHash}}`;
  const now = Date.now();
  const result: unknown = await client.eval(REDIS_RATE_LIMIT_SCRIPT, {
    keys: [`${keyPrefix}:requests`, `${keyPrefix}:blocked`],
    arguments: [
      String(now),
      String(windowMs),
      String(maxRequests),
      String(blockDurationMs),
      `${now}:${randomUUID()}`,
    ],
  });

  if (!Array.isArray(result) || result.length !== 3) {
    throw new Error("Redis returned an invalid rate limit result.");
  }

  const [allowedValue, remainingValue, resetValue] = result;
  const success = Number(allowedValue) === 1;
  const remaining = Number(remainingValue);
  const resetMs = Number(resetValue);
  if (
    !Number.isFinite(remaining) ||
    !Number.isFinite(resetMs) ||
    remaining < 0 ||
    resetMs < 0
  ) {
    throw new Error("Redis returned invalid rate limit values.");
  }

  return {
    success,
    remaining,
    resetMs,
    retryAfterMs: success ? undefined : resetMs,
  };
}

/**
 * Check a rate limit using shared Redis when REDIS_URL is configured, and
 * fall back to per-process memory otherwise (including production, so the
 * app stays usable without Redis — limits are then per serverless instance).
 */
export async function checkRateLimit(
  identifier: string,
  config: RateLimitConfig
): Promise<RateLimitResult> {
  if (process.env.REDIS_URL) {
    return checkRedisRateLimit(identifier, config);
  }

  if (process.env.NODE_ENV !== "test" && !warnedAboutMemoryFallback) {
    console.warn(
      "REDIS_URL is not configured; API rate limits are local to this server process. Set REDIS_URL for shared rate limiting."
    );
    warnedAboutMemoryFallback = true;
  }

  return checkInMemoryRateLimit(identifier, config);
}

/** Reset in-memory rate limit stores (useful in test suites). */
export function resetRateLimitStoreForTesting(): void {
  stores.clear();
}

/** Extract a client identifier from the proxy IP headers. */
export function getClientIdentifier(headers: Headers): string {
  const forwarded = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (forwarded) return forwarded;
  const realIp = headers.get("x-real-ip")?.trim();
  return realIp || "anonymous";
}

/** Convenience helper to return a standardized 429 JSON response with proper headers. */
export function createRateLimitResponse(
  limit: RateLimitResult,
  customMessage?: string
): NextResponse {
  const retrySec = Math.max(1, Math.ceil((limit.retryAfterMs ?? 30_000) / 1000));
  return NextResponse.json(
    {
      error:
        customMessage ||
        `Rate limit exceeded. Please wait ${retrySec} second${retrySec === 1 ? "" : "s"} before retrying.`,
      isError: true,
      retryAfterMs: limit.retryAfterMs,
    },
    {
      status: 429,
      headers: {
        "Retry-After": String(retrySec),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": String(Math.ceil(limit.resetMs / 1000)),
      },
    }
  );
}

/** Apply rate limiting to a route and fail closed if protection is unavailable. */
export async function enforceRateLimit(
  request: NextRequest,
  config: RateLimitConfig,
  customMessage?: string
): Promise<EnforcedRateLimit> {
  try {
    const limit = await checkRateLimit(
      getClientIdentifier(request.headers),
      config
    );
    if (!limit.success) {
      return {
        success: false,
        response: createRateLimitResponse(limit, customMessage),
      };
    }
    return { success: true, limit };
  } catch (error: unknown) {
    console.error(
      `Rate limit protection unavailable for ${config.name ?? "default"}:`,
      error
    );
    return {
      success: false,
      response: NextResponse.json(
        { error: "Request protection is temporarily unavailable.", isError: true },
        { status: 503, headers: { "Retry-After": "30" } }
      ),
    };
  }
}

/** Chat API: 10 requests per 60 seconds per client */
export const CHAT_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 10,
  windowMs: 60_000,
  blockDurationMs: 30_000,
  name: "chat-api",
};

/** Simulation Advise API: 15 requests per 60 seconds per client */
export const ADVISE_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 15,
  windowMs: 60_000,
  blockDurationMs: 20_000,
  name: "sim-advise",
};

/** General API: 60 requests per 60 seconds per client */
export const GENERAL_API_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 60,
  windowMs: 60_000,
  blockDurationMs: 15_000,
  name: "general-api",
};

/** Supabase DB queries: 30 requests per 60 seconds per client */
export const DB_RATE_LIMIT: RateLimitConfig = {
  maxRequests: 30,
  windowMs: 60_000,
  blockDurationMs: 20_000,
  name: "db-queries",
};
