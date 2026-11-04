import test from "node:test";
import assert from "node:assert/strict";
import { isAllowedFrontendOrigin } from "../src/origins.js";

const configuredOrigins = new Set(["https://classtrack.example.com"]);

test("configured origins are allowed", () => {
  assert.equal(
    isAllowedFrontendOrigin("https://classtrack.example.com", configuredOrigins, false),
    true
  );
});

test("local development frontends may use other localhost ports", () => {
  assert.equal(isAllowedFrontendOrigin("http://localhost:5500", configuredOrigins, true), true);
  assert.equal(isAllowedFrontendOrigin("http://127.0.0.1:5173", configuredOrigins, true), true);
});

test("untrusted and non-development origins remain blocked", () => {
  assert.equal(isAllowedFrontendOrigin("http://localhost.evil:5500", configuredOrigins, true), false);
  assert.equal(isAllowedFrontendOrigin("https://localhost:5500", configuredOrigins, true), false);
  assert.equal(isAllowedFrontendOrigin("http://localhost:5500", configuredOrigins, false), false);
  assert.equal(isAllowedFrontendOrigin("http://localhost:5500/path", configuredOrigins, true), false);
});
