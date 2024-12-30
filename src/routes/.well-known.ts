import { Router } from "express";
import { sendOK } from "guzek-uk-common/util";
import { getPublicKey } from "../keys";

export const router = Router();

// GET JWKS public key
router.get("/jwks.json", (_req, res) =>
  sendOK(res, { keys: [getPublicKey()] })
);