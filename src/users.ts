import { Response } from "express";
import type { UserObj } from "guzek-uk-common/models";
import { User } from "guzek-uk-common/lib/sequelize";
import { readAllDatabaseEntries } from "guzek-uk-common/lib/rest";
import { sendOK } from "guzek-uk-common/lib/http";

function sanitiseUser(user: User): UserObj {
  const { hash, salt, ...publicProperties } = user.get();
  return publicProperties;
}
/** Converts the database record or records into an object or array of objects without hash or salt properties. */
export function removeSensitiveData<T extends User | User[]>(
  record: T
): T extends User ? UserObj : UserObj[];

export function removeSensitiveData(record: User | User[]) {
  return Array.isArray(record)
    ? record.map(sanitiseUser)
    : sanitiseUser(record);
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
