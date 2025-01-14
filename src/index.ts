import ExpoScryptModule from "./ExpoScryptModule";

export interface ScryptOptions {
  N: number; // CPU/memory cost parameter
  r: number; // Block size parameter
  p: number; // Parallelization parameter
  dkLen: number; // Desired key length in bytes
}

export type ProgressCallback = (progress: number) => void;

export async function scrypt(
  password: ArrayLike<number>,
  salt: ArrayLike<number>,
  N: number,
  r: number,
  p: number,
  dkLen: number,
  callback?: ProgressCallback
): Promise<Uint8Array> {
  // Convert ArrayLike<number> to base64 strings for native modules
  const passwordArray = Array.from(password);
  const saltArray = Array.from(salt);
  const passwordBase64 = Buffer.from(passwordArray).toString("base64");
  const saltBase64 = Buffer.from(saltArray).toString("base64");

  const byteArray = await ExpoScryptModule.scrypt(
    passwordBase64,
    saltBase64,
    { N, r, p, dkLen },
    callback
  );

  return new Uint8Array(byteArray);
}

export default {
  scrypt,
};
