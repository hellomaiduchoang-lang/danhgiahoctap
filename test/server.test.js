import test from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { app } from "../src/server.js";

async function startServer(t) {
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

test("GET /health returns the liveness response", async (t) => {
  const origin = await startServer(t);
  const response = await fetch(`${origin}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
});

test("GET / serves the existing frontend", async (t) => {
  const origin = await startServer(t);
  const response = await fetch(`${origin}/`);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);
  assert.match(response.headers.get("content-security-policy"), /script-src 'self' 'unsafe-inline'/);
  assert.match(await response.text(), /ClassTrack/);
});

test("auth endpoints validate login and require a real session", async (t) => {
  const origin = await startServer(t);
  const invalidLogin = await fetch(`${origin}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "ab", password: "invalid" })
  });
  assert.equal(invalidLogin.status, 400);
  assert.equal((await invalidLogin.json()).error, "Tên đăng nhập hoặc mật khẩu không hợp lệ.");

  const session = await fetch(`${origin}/api/session`);
  assert.equal(session.status, 401);
  assert.deepEqual(await session.json(), { error: "Authentication required." });

  const configuredDatabaseUrl = process.env.DATABASE_URL;
  delete process.env.DATABASE_URL;
  try {
    const unavailableLogin = await fetch(`${origin}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "a-valid-password" })
    });
    assert.equal(unavailableLogin.status, 503);
    assert.deepEqual(await unavailableLogin.json(), {
      error: "DATABASE_URL chưa được cấu hình; hãy đặt URL PostgreSQL trước khi dùng API xác thực.",
      code: "DATABASE_NOT_CONFIGURED"
    });
  } finally {
    if (configuredDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = configuredDatabaseUrl;
  }

  const logout = await fetch(`${origin}/api/auth/logout`, { method: "POST" });
  assert.equal(logout.status, 204);
  assert.match(logout.headers.get("set-cookie"), /HttpOnly; SameSite=Lax; Path=\//);
});

test("unimplemented API endpoints return a clear JSON response", async (t) => {
  const origin = await startServer(t);
  const response = await fetch(`${origin}/api/classes`);
  assert.equal(response.status, 501);
  assert.equal((await response.json()).code, "NOT_IMPLEMENTED");
});

test("malformed JSON uses the standard error response", async (t) => {
  const origin = await startServer(t);
  const response = await fetch(`${origin}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{invalid"
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: "JSON request không hợp lệ.",
    code: "BAD_REQUEST"
  });
});
