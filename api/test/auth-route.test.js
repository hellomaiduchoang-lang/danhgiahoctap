import test from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/server.js";

test("POST /api/auth/login parses JSON and reaches the login handler", async () => {
  const server = app.listen(0, "127.0.0.1");

  try {
    await new Promise((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });

    const address = server.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ab", password: "invalid" })
    });

    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      error: "Tên đăng nhập hoặc mật khẩu không hợp lệ.",
      code: "BAD_REQUEST"
    });

    const getResponse = await fetch(`http://127.0.0.1:${address.port}/api/auth/login`);
    assert.equal(getResponse.status, 404);
    assert.deepEqual(await getResponse.json(), {
      error: "API route not found.",
      code: "NOT_FOUND"
    });
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
