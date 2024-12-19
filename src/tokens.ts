import { WhereOptions } from "sequelize";
import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";

import { UserObj } from "guzek-uk-common/models";
import { Token, User } from "guzek-uk-common/sequelize";
import { queryDatabase, sendError, sendOK } from "guzek-uk-common/util";

import password from "s-salt-pepper";
import { Response } from "express";
import { getPrivateKey, getRefreshSecret } from "./keys";

/** The number of milliseconds a newly-generated access token should be valid for. */
const TOKEN_VALID_FOR_MS = 30 * 60 * 1000; // 30 mins

/** Authenticate given password against the stored credentials in the database. */
export async function authenticateUser(
  res: Response,
  where: WhereOptions,
  pw: string
) {
  if (!pw) {
    throw Error("Password not provided.");
  }
  const records = await queryDatabase(User, { where }, () => {
    const property = Object.keys(where).shift();
    sendError(res, 400, { message: `Invalid ${property}.` });
  });
  if (!records) return;
  const userRecord = records[0];
  const { hash, salt, ...userDetails } = userRecord.get();
  const isValid = await password.compare(pw, { hash, salt });
  if (!isValid) throw Error("Invalid password.");
  return userDetails;
}

/** Generate a new access token. Called when logging in, creating a new account, or refreshing a previous token. */
export function generateAccessToken(user: UserObj) {
  const payload = { ...user, iat: new Date().getTime() };
  const signOptions = {
    expiresIn: TOKEN_VALID_FOR_MS,
    algorithm: "RS256",
    header: { kid: "v1", alg: "RS256" },
  } satisfies SignOptions;
  const accessToken = jwt.sign(payload, getPrivateKey(), signOptions);
  const tokenInfo = jwt.decode(accessToken) as JwtPayload;
  return { accessToken, expiresAt: tokenInfo.exp };
}

/** Send new access and refresh tokens to the client. Called when logging in or creating a new account. */
export function sendNewTokens(res: Response, user: UserObj) {
  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, getRefreshSecret());
  Token.create({ value: refreshToken }).then();
  sendOK(res, { ...user, ...accessToken, refreshToken }, 201);
}
