import express from "express";
import type { Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { Op } from "sequelize";
import { verify } from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import {
  createDatabaseEntry,
  queryDatabase,
  updateDatabaseEntry,
  deleteDatabaseEntry,
  findUnique,
} from "guzek-uk-common/lib/rest";
import { sendError, sendOK } from "guzek-uk-common/lib/http";
import {
  UserShows,
  Token,
  User,
  WatchedEpisodes,
} from "guzek-uk-common/lib/sequelize";
import type { CustomRequest, UserObj } from "guzek-uk-common/models";
import { getLogger } from "guzek-uk-common/lib/logger";
import password from "s-salt-pepper";
import {
  authenticateUser,
  clearTokenCookies,
  generateAccessToken,
  sendNewTokens,
  setTokenCookies,
} from "../tokens";
import { removeSensitiveData, sendUsers } from "../users";
import { getRefreshSecret } from "../keys";

export const router = express.Router();
const logger = getLogger(__filename);

const MODIFIABLE_USER_PROPERTIES = ["username", "email", "serverUrl"];

const ADMIN_ONLY_USER_PROPERTIES = ["uuid", "admin"];

const JWT_PAYLOAD_USER_PROPERTIES = [
  "uuid",
  "username",
  "email",
  "admin",
] as const;

const EMAIL_REGEX = /^[^@]+@[^@]+\.[^@]+$/;
const USERNAME_REGEX = /^[a-zA-Z0-9-_\.]{2,}[a-zA-Z0-9]$/;

// CREATE new account
router.post("/users", async (req: Request, res: Response) => {
  for (const requiredProperty of ["username", "email", "password"]) {
    if (!req.body[requiredProperty]) {
      return sendError(res, 400, {
        message: `Invalid account details. No ${requiredProperty} specified.`,
      });
    }
  }

  if (!EMAIL_REGEX.test(req.body.email)) {
    return sendError(res, 400, {
      message: "Invalid email address format.",
    });
  }

  if (!USERNAME_REGEX.test(req.body.username)) {
    return sendError(res, 400, {
      message:
        "Username must: be at least three characters long; contain only letters, numbers, underscores, hyphens, and dots; and end with a letter or number.",
    });
  }

  // Check for existing entries
  const results = await queryDatabase(User, {
    where: {
      [Op.or]: [{ email: req.body.email }, { username: req.body.username }],
    },
  });
  const existingUser = results?.shift();

  if (existingUser != null) {
    const taken = existingUser.email === req.body.email ? "email" : "username";
    return sendError(res, 400, {
      message: `That ${taken} is taken.`,
    });
  }
  const credentials = await password.hash(req.body.password);

  await createDatabaseEntry(
    User,
    {
      uuid: uuidv4(),
      username: req.body.username,
      email: req.body.email,
      ...credentials,
    },
    res,
    (_res: Response, record: User) => {
      sendNewTokens(req, res, removeSensitiveData(record));
    }
  );
});

// READ currently authenticated user
router.get("/users/me", (req: CustomRequest, res: Response) => {
  req.user
    ? sendOK(res, req.user)
    : sendError(res, 401, {
        message: "You must be logged in to access your user details.",
      });
});

// READ all users
router.get("/users", (_req: Request, res: Response) => {
  sendUsers(res, false);
});

// READ specific user by search query
router.get("/users", async (req: Request, res: Response) => {
  const results = await queryDatabase(User, { where: req.query }, res);
  if (results) sendOK(res, removeSensitiveData(results[0]));
});

// READ specific user by uuid
router.get("/users/:uuid", async (req: Request, res: Response) => {
  const user = await findUnique(User, req.params.uuid);
  if (!user) {
    sendError(res, 404, {
      message: `There is no user with uuid '${req.params.uuid}'.`,
    });
    return;
  }
  sendOK(res, removeSensitiveData(user));
});

function getUserQuery(req: CustomRequest) {
  if (req.params.uuid === "me") {
    if (!req.user) {
      logger.error("Unauthenticated user accessed /auth/users/me endpoint.");
      throw new Error("Security breach in /auth/users/me");
    }
    return { uuid: req.user.uuid };
  }
  return { uuid: req.params.uuid };
}

// UPDATE existing user details
router.put(
  "/users/:uuid/details",
  async (req: CustomRequest, res: Response) => {
    for (const property in req.body) {
      if (MODIFIABLE_USER_PROPERTIES.includes(property)) continue;
      if (ADMIN_ONLY_USER_PROPERTIES.includes(property)) {
        if (req.user?.admin) continue;
        return sendError(res, 403, {
          message: `Protected user property '${property}'.`,
        });
      }

      return sendError(res, 400, {
        message: `Unmodifiable user property '${property}'.`,
      });
    }

    await updateDatabaseEntry(
      User,
      req,
      res,
      req.body,
      getUserQuery(req),
      "/profile"
    );
  }
);

// UPDATE existing user password
router.put(
  "/users/:uuid/password",
  async (req: CustomRequest, res: Response) => {
    const reject = (message: string) => sendError(res, 400, { message });

    const query = getUserQuery(req);

    if (!req.user?.admin) {
      if (!req.body.oldPassword) return reject("Old password not provided.");

      // Validate the old password
      try {
        const success = await authenticateUser(
          res,
          query,
          req.body.oldPassword
        );
        if (!success) return;
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        const { message } = error;
        // Update the error message to better reflect the situation
        return reject(message.replace(/^Password/, "Old password"));
      }
    }

    const credentials = await password.hash(req.body.newPassword);
    await updateDatabaseEntry(User, req, res, credentials, query, "/profile");
  }
);

// DELETE existing user
router.delete("/users/:uuid", async (req: CustomRequest, res: Response) => {
  const query = getUserQuery(req);
  if (!query.uuid)
    return sendError(res, 400, {
      message: "User UUID must be provided in request path.",
    });
  try {
    await deleteDatabaseEntry(UserShows, { userUuid: query.uuid });
    await deleteDatabaseEntry(WatchedEpisodes, { userUuid: query.uuid });
  } catch (error) {
    logger.error(`Could not delete user-associated entries:`, error);
  }
  let redirect = "/admin/users";
  if (query.uuid === req.user?.uuid) {
    redirect = "/login";
    clearTokenCookies(res);
  }
  await deleteDatabaseEntry(User, query, res, req, redirect);
});

// READ all usernames
router.get("/usernames", (_req: Request, res: Response) => {
  sendUsers(res, true);
});

// CREATE refresh token (log in)
router.post("/tokens", async (req: Request, res: Response) => {
  const reject = (message: string) => sendError(res, 400, { message });

  const { password, email, login } = req.body;

  if (!login && !email) return reject("Login not provided.");

  // Supports 'email' key for backwards compatibility
  const query = email
    ? { email }
    : EMAIL_REGEX.test(login)
    ? { email: login }
    : { username: login };
  let userData;
  try {
    userData = await authenticateUser(res, query, password);
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    return void reject(error.message);
  }
  if (!userData) return;
  const user = await findUnique(User, userData.uuid);
  if (!user) return;
  sendNewTokens(req, res, removeSensitiveData(user));
});

async function deleteRefreshToken(
  req: Request,
  res: Response,
  refreshToken: string
) {
  const reject = (message: string) => sendError(res, 400, { message });
  if (!refreshToken) {
    reject("No refresh token provided.");
    return;
  }
  verify(refreshToken, getRefreshSecret(), (err, payload) => {
    if (err || !isUserObj(payload))
      return reject("Invalid or expired refresh token.");
    clearTokenCookies(res);
    deleteDatabaseEntry(Token, { value: refreshToken }, res, req, "/login");
  });
}

// DELETE refresh token using body or cookies
router.delete("/tokens", (req: Request, res: Response) => {
  const refreshToken = req.body.token || req.cookies.refresh_token;
  deleteRefreshToken(req, res, refreshToken);
});

// DELETE refresh token using path (deprecated)
router.delete("/tokens/:token", (req: Request, res: Response) => {
  const refreshToken = req.params.token;
  deleteRefreshToken(req, res, refreshToken);
});

const isUserObj = (
  payload: string | JwtPayload | undefined
): payload is UserObj =>
  typeof payload === "object" &&
  payload != null &&
  JWT_PAYLOAD_USER_PROPERTIES.every((key) => key in payload);

// CREATE new access JWT
router.post("/refresh", async (req: Request, res: Response) => {
  const reject = (message: string) => sendError(res, 400, { message });

  const refreshToken = req.body.token || req.cookies.refresh_token;
  if (!refreshToken) return reject("No refresh token provided.");
  const tokens = await queryDatabase(
    Token,
    { where: { value: refreshToken } },
    () => {
      reject("The provided refresh token was not issued by this server.");
    }
  );
  if (!tokens) return;
  verify(refreshToken as string, getRefreshSecret(), async (err, payload) => {
    if (err) return reject("Invalid or expired refresh token.");
    if (!isUserObj(payload)) {
      return sendError(res, 400, {
        message: "The refresh token payload does not contain a user object.",
      });
    }
    // Ensure the access token has the latest user details
    const userRecord = await findUnique(User, payload.uuid);
    if (!userRecord) {
      return sendError(res, 400, {
        message:
          "The refresh token was issued to a user who has since been deleted.",
      });
    }
    const user = removeSensitiveData(userRecord);
    const { accessToken, expiresAt } = generateAccessToken(user);
    setTokenCookies(res, accessToken);
    sendOK(res, { accessToken, expiresAt, user }, 201);
  });
});
