import "dotenv/config";
import express from "express";
import helmet from "helmet";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { authRouter, getSession } from "./routes/auth.js";

const app = express();
const port = Number(process.env.PORT || 3000);
const host = "0.0.0.0";
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const publicDirectory = path.join(projectRoot, "public");

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_request, response) => {
  response.json({ ok: true });
});

app.use("/api/auth", authRouter);
app.get("/api/session", getSession);

app.use("/api", (request, response) => {
  response.status(501).json({
    error: `API ${request.method} ${request.path} chưa được triển khai trong backend tối thiểu.`,
    code: "NOT_IMPLEMENTED"
  });
});

app.get("/", (_request, response, next) => {
  response.sendFile(path.join(publicDirectory, "index.html"), (error) => {
    if (error) next(error);
  });
});
app.use(express.static(publicDirectory, { index: false }));

app.use((_request, response) => {
  response.status(404).json({
    error: "Không tìm thấy tài nguyên.",
    code: "NOT_FOUND"
  });
});

app.use((error, _request, response, _next) => {
  if (response.headersSent) return;
  if (error.code === "DATABASE_NOT_CONFIGURED") {
    response.status(503).json({ error: error.message, code: error.code });
    return;
  }
  console.error("Request failed:", error);
  const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 500
    ? error.status
    : 500;
  const messages = {
    400: { error: "JSON request không hợp lệ.", code: "BAD_REQUEST" },
    413: { error: "Request vượt quá giới hạn kích thước.", code: "PAYLOAD_TOO_LARGE" }
  };
  response.status(status).json(messages[status] || {
    error: "Đã xảy ra lỗi máy chủ.",
    code: "INTERNAL_SERVER_ERROR"
  });
});

const isMainModule = process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMainModule) {
  app.listen(port, host, () => {
    console.info(`ClassTrack minimal server listening on ${host}:${port}`);
  });
}

export { app };
