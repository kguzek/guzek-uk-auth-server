import { WhereOptions } from "sequelize";
import jwt, { SignOptions } from "jsonwebtoken";

import { UserObj } from "guzek-uk-common/models";
import { Token, User } from "guzek-uk-common/lib/sequelize";
import { queryDatabase } from "guzek-uk-common/lib/rest";
import { sendError, sendOK } from "guzek-uk-common/lib/http";

import password from "s-salt-pepper";
import { CookieOptions, Request, Response } from "express";
import { getPrivateKey, getRefreshSecret } from "./keys";

/** The number of milliseconds a newly-generated access token should be valid for. */
const TOKEN_VALID_FOR_MS = 30 * 60 * 1000; // 30 mins
/** The number of milliseconds a newly-generated refresh token should be valid for. */
const REFRESH_TOKEN_VALID_FOR_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/** Set or clear a cookie in the response. */
function setCookie(
  res: Response,
  name: string,
  ...[value, maxAge]: [] | [string, number]
) {
  const options: CookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge,
    path: "/",
    domain: process.env.COOKIE_DOMAIN || "guzek.uk",
  };
  if (value && maxAge) {
    res.cookie(name, value, options);
  } else {
    res.clearCookie(name, options);
  }
}

/** Clear the access and refresh tokens from the response. */
export function clearTokenCookies(res: Response) {
  setCookie(res, "access_token");
  setCookie(res, "refresh_token");
  // Backwards compatibility with old cookie name
  setCookie(res, "user");
}

/** Set the access and refresh tokens as HTTP-only cookies in the response. */
export function setTokenCookies(
  res: Response,
  accessToken: string,
  refreshToken?: string
) {
  setCookie(res, "access_token", accessToken, TOKEN_VALID_FOR_MS);
  if (!refreshToken) return;
  setCookie(res, "refresh_token", refreshToken, REFRESH_TOKEN_VALID_FOR_MS);
}

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
  if (!records) return null;
  const userRecord = records[0];
  const { hash, salt, ...userDetails } = userRecord.get();
  const isValid = await password.compare(pw, { hash, salt });
  if (!isValid) throw Error("Invalid password.");
  return userDetails as UserObj;
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
  const tokenInfo = jwt.decode(accessToken);
  if (!tokenInfo) throw Error("Failed to decode access token.");
  if (typeof tokenInfo === "string") throw Error("Token info is a string.");
  return { accessToken, expiresAt: tokenInfo.exp };
}

/** Send new access and refresh tokens to the client. Called when logging in or creating a new account. */
export function sendNewTokens(req: Request, res: Response, user: UserObj) {
  const { accessToken, expiresAt } = generateAccessToken(user);
  const refreshToken = jwt.sign(user, getRefreshSecret());
  Token.create({ value: refreshToken }).then();
  setTokenCookies(res, accessToken, refreshToken);
  sendOK(
    res,
    { ...user, accessToken, expiresAt, refreshToken },
    201,
    req,
    "/profile"
  );
}
