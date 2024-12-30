import type { Request, RequestHandler } from "express";

const AUTH_ENDPOINTS_WITH_CREDENTIALS = ["/users", "/tokens", "/refresh"];

const shouldAllowCredentials = (req: Request) =>
  ["OPTIONS", "POST"].includes(req.method) &&
  AUTH_ENDPOINTS_WITH_CREDENTIALS.includes(req.path);

/** This prevents browsers from rejecting responses to requests that use credentials. */
export const allowCredentialsCors: RequestHandler = (req, res, next) => {
  if (shouldAllowCredentials(req)) {
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
};
