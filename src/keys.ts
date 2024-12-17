import fs from "fs";
import crypto, { JsonWebKey } from "crypto";
import { Secret } from "jsonwebtoken";

const PRIVATE_KEY_PATH = "./private-access.key";
const PUBLIC_KEY_PATH = "./public-access.key";
const PRIVATE_KEY_PASSPHRASE = process.env.JWT_PASSPHRASE;

let privateKey: crypto.KeyObject;
let publicKey: JsonWebKey;

/** Returns the decrypted private key to be used for signing JWTs. */
export function getPrivateKey() {
  if (privateKey) return privateKey;
  const encryptedPrivateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
  privateKey = crypto.createPrivateKey({
    key: encryptedPrivateKey,
    passphrase: PRIVATE_KEY_PASSPHRASE,
  });
  return privateKey;
}

// Function to convert Base64 to Base64URL
function base64ToBase64URL(base64?: string) {
  return (
    base64 && base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
  );
}

/** Returns the public key to be served as a JWKS response. */
export function getPublicKey() {
  const encryptedPublicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
  const publicKeyObject = crypto.createPublicKey(encryptedPublicKey);
  const jwk = publicKeyObject.export({ format: "jwk" });
  publicKey = {
    kty: jwk.kty, // Key type
    kid: "v1", // Key ID (you can generate this or assign it)
    use: "sig", // The key is used for signing JWTs
    alg: "RS256", // The algorithm (RS256 in this case)
    n: base64ToBase64URL(jwk.n), // The modulus in PEM format
    e: base64ToBase64URL(jwk.e), // The exponent in base64 (e.g., 65537)
  };
  return publicKey;
}

export const getRefreshSecret = (): Secret =>
  process.env.JWT_REFRESH_TOKEN_SECRET || "";
