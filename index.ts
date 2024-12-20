import express from "express";
import password from "s-salt-pepper";
import { setupEnvironment } from "guzek-uk-common/setup";
setupEnvironment();
import { getLogger } from "guzek-uk-common/logger";
import { getMiddleware } from "guzek-uk-common/middleware";
import { startServer } from "guzek-uk-common/server";
import { send405 } from "guzek-uk-common/util";
import { router as authRouter } from "./src/routes/auth";
import { router as wellKnownRouter } from "./src/routes/.well-known";

const logger = getLogger(__filename);

const app = express();

async function initialise() {
  const iterations = process.env.HASH_ITERATIONS;
  if (!iterations) {
    logger.error("No HASH_ITERATIONS environment variable set.");
    return;
  }

  password.iterations(parseInt(iterations));
  password.pepper(process.env.HASH_PEPPER);

  app.use(getMiddleware());
  app.use("/auth", authRouter, send405);
  app.use("/.well-known", wellKnownRouter, send405);

  startServer(app);
}

initialise();
