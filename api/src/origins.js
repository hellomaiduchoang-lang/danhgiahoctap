export function isAllowedFrontendOrigin(origin, allowedOrigins, isDevelopment) {
  if (allowedOrigins.has(origin)) return true;
  if (!isDevelopment || typeof origin !== "string") return false;

  try {
    const url = new URL(origin);
    return url.origin === origin &&
      url.protocol === "http:" &&
      ["localhost", "127.0.0.1"].includes(url.hostname);
  } catch {
    return false;
  }
}
