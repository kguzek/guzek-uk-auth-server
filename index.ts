import express from "express";
import dotenv from "dotenv";
dotenv.config();
import password from "s-salt-pepper";
import { getLogger } from "guzek-uk-common/logger";
import { getMiddleware } from "guzek-uk-common/middleware";
import { sendOK, startServer } from "guzek-uk-common/util";
import { router as authRouter } from "./src/route";
import { getPublicKey } from "./src/keys";

const logger = getLogger(__filename);

const app = express();

// Determine the server port
const PORT = process.env.NODE_PORT;

function initialise() {
  const iterations = process.env.HASH_ITERATIONS;
  if (!iterations) {
    logger.error("No HASH_ITERATIONS environment variable set.");
    return;
  }

  password.iterations(parseInt(iterations));
  password.pepper(process.env.HASH_PEPPER);

  app.set("trust proxy", 1);
  app.use(getMiddleware());
  app.use("/auth", authRouter);

  // GET JWKS public key
  app.get("/.well-known/jwks.json", (_req, res) =>
    sendOK(res, { keys: [getPublicKey()] })
  );

  startServer(app, PORT);
}

if (PORT) {
  initialise();
} else {
  logger.error("No server port environment variable set.");
}
