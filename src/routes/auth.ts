import express, { Request, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import { verify } from "jsonwebtoken";
import {
  createDatabaseEntry,
  queryDatabase,
  updateDatabaseEntry,
  deleteDatabaseEntry,
  sendError,
  sendOK,
} from "guzek-uk-common/util";
import {
  UserShows,
  Token,
  User,
  WatchedEpisodes,
} from "guzek-uk-common/sequelize";
import { CustomRequest, UserObj } from "guzek-uk-common/models";
import { getLogger } from "guzek-uk-common/logger";
import password from "s-salt-pepper";
import {
  authenticateUser,
  generateAccessToken,
  sendNewTokens,
} from "../tokens";
import { removeSensitiveData, sendUsers } from "../users";
import { getRefreshSecret } from "../keys";

export const router = express.Router();
const logger = getLogger(__filename);

const MODIFIABLE_USER_PROPERTIES = ["username", "email", "serverUrl"];

const ADMIN_ONLY_USER_PROPERTIES = [
  "uuid",
  "admin",
  "created_at",
  "modified_at",
];

// CREATE new account
router.post("/users", async (req: Request, res: Response) => {
  for (const requiredProperty of ["username", "email", "password"]) {
    if (!req.body[requiredProperty]) {
      return sendError(res, 400, {
        message: `Invalid account details. No ${requiredProperty} specified.`,
      });
    }
  }
  // Check for existing entries
  const results = await queryDatabase(User, {
    where: { email: req.body.email },
  });

  if (results?.shift()) {
    return sendError(res, 400, {
      message: "A user with that email address already exists.",
    });
  }
  // Hash password
  const credentials: { hash: string; salt: string } = await password.hash(
    req.body.password
  );

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
      const { hash, salt, ...userData } = record.get();
      sendNewTokens(res, userData);
    }
  );
});

// READ all users
router.get("/users", (_req: Request, res: Response) => {
  sendUsers(res, false);
});

// READ specific user by search query
router.get("/users", async (req: Request, res: Response) => {
  const results = await queryDatabase(User, { where: req.query }, res);
  if (results) sendOK(res, removeSensitiveData(results)[0]);
});

// READ specific user by uuid
router.get("/users/:uuid", async (req: Request, res: Response) => {
  const results = await queryDatabase(User, { where: req.params }, res);
  if (results) sendOK(res, removeSensitiveData(results));
});

// UPDATE existing user details
router.put(
  "/users/:uuid/details",
  async (req: CustomRequest, res: Response) => {
    for (const property in req.body) {
      if (MODIFIABLE_USER_PROPERTIES.includes(property)) continue;
      if (!req.user?.admin) {
        return sendError(res, 403, {
          message: `Protected user property '${property}'.`,
        });
      }
      if (ADMIN_ONLY_USER_PROPERTIES.includes(property)) continue;

      return sendError(res, 400, {
        message: `Unmodifiable user property '${property}'.`,
      });
    }

    await updateDatabaseEntry(User, req, res);
  }
);

// UPDATE existing user password
router.put(
  "/users/:uuid/password",
  async (req: CustomRequest, res: Response) => {
    const reject = (message: string) => sendError(res, 400, { message });

    if (!req.user?.admin) {
      if (!req.body.oldPassword) return reject("Old password not provided.");

      // Validate the old password
      try {
        const success = await authenticateUser(
          res,
          req.params,
          req.body.oldPassword
        );
        if (!success) return;
      } catch (error) {
        const { message } = error as Error;
        // Update the error message to better reflect the situation
        return reject(message.replace(/^Password/, "Old password"));
      }
    }

    const credentials: { hash: string; salt: string } = await password.hash(
      req.body.newPassword
    );
    await updateDatabaseEntry(
      User,
      { params: req.params, body: credentials } as Request,
      res
    );
  }
);

// DELETE existing user
router.delete("/users/:uuid", async (req: Request, res: Response) => {
  const uuid = req.params.uuid;
  if (!uuid)
    return sendError(res, 400, {
      message: "User UUID must be provided in request path.",
    });
  try {
    await deleteDatabaseEntry(UserShows, { userUUID: uuid });
    await deleteDatabaseEntry(WatchedEpisodes, { userUUID: uuid });
  } catch (error) {
    logger.error(`Could not delete user-associated entries: ${error}`);
  }
  await deleteDatabaseEntry(User, { uuid }, res);
});

// READ all usernames
router.get("/usernames", (_req: Request, res: Response) => {
  sendUsers(res, true);
});

// CREATE refresh token
router.post("/tokens", async (req: Request, res: Response) => {
  const reject = (message: string) => sendError(res, 400, { message });

  const { password: pw, email } = req.body;

  if (!email) return reject("Email not provided.");

  let userData;
  try {
    userData = await authenticateUser(res, { email }, pw);
  } catch (err) {
    return void reject((err as Error).message);
  }
  if (!userData) return;
  sendNewTokens(res, userData);
});

// DELETE refresh token
router.delete("/tokens/:token", async (req: Request, res: Response) => {
  const reject = (message: string) => sendError(res, 400, { message });
  const refreshToken = req.params.token;
  if (!refreshToken) return void reject("No refresh token provided.");

  await deleteDatabaseEntry(Token, { value: refreshToken }, res);
});

// CREATE new access JWT
router.post("/refresh", async (req: Request, res: Response) => {
  const reject = (message: string) => sendError(res, 400, { message });

  const refreshToken = req.body.token;
  if (!refreshToken) return reject("No refresh token provided.");
  const tokens = await queryDatabase(
    Token,
    { where: { value: refreshToken } },
    () => {
      reject("The provided refresh token was not issued by this server.");
    }
  );
  if (!tokens) return;
  verify(refreshToken as string, getRefreshSecret(), (err, user) => {
    if (err) return reject("Invalid or expired refresh token.");

    sendOK(res, generateAccessToken(user as UserObj), 201);
  });
});
