import { Response } from "express";
import type { UserObj } from "guzek-uk-common/models";
import { User } from "guzek-uk-common/sequelize";
import { readAllDatabaseEntries, sendOK } from "guzek-uk-common/util";

function sanitiseUser(user: User): UserObj {
  const { hash, salt, ...publicProperties } = user.get();
  return publicProperties;
}

export function removeSensitiveData<T extends User | User[]>(
  data: T
): T extends User ? UserObj : UserObj[];

export function removeSensitiveData(data: User | User[]) {
  return Array.isArray(data) ? data.map(sanitiseUser) : sanitiseUser(data);
}

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
