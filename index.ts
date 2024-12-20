import express from "express";
import password from "s-salt-pepper";
import { setupEnvironment } from "guzek-uk-common/setup";
setupEnvironment();
import { getLogger } from "guzek-uk-common/logger";
import { getMiddleware } from "guzek-uk-common/middleware";
import { startServer } from "guzek-uk-common/server";
import { send405 } from "guzek-uk-common/util";

const logger = getLogger(__filename);

const app = express();

const ENDPOINTS = ["auth", ".well-known"];

async function initialise() {
  const iterations = process.env.HASH_ITERATIONS;
  if (!iterations) {
    logger.error("No HASH_ITERATIONS environment variable set.");
    return;
  }

  password.iterations(parseInt(iterations));
  password.pepper(process.env.HASH_PEPPER);

  app.use(getMiddleware());
  for (const endpoint of ENDPOINTS) {
    const middleware = await import("./src/routes/" + endpoint);
    if (middleware.init) middleware.init(ENDPOINTS);
    app.use(`/${endpoint}`, middleware.router, send405);
  }

  startServer(app, ENDPOINTS);
}

initialise();
