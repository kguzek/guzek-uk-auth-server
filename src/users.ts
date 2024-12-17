import { Response } from "express";
import { User } from "guzek-uk-common/sequelize";
import { readAllDatabaseEntries, sendOK } from "guzek-uk-common/util";

export const removeSensitiveData = (users: User[]) =>
  users.map((user) => {
    const { hash, salt, ...publicProperties } = user.get();
    return publicProperties;
  });

export const sendUsers = (res: Response, returnOnlyUsernames: boolean) =>
  readAllDatabaseEntries(User, res, (users) => {
    sendOK(
      res,
      returnOnlyUsernames
        ? Object.fromEntries(
            users.map((user: User) => [user.get("uuid"), user.get("username")])
          )
        : removeSensitiveData(users)
    );
  });
