import ExpoScryptModule from "./ExpoScryptModule";

export interface ScryptOptions {
  N: number; // CPU/memory cost parameter
  r: number; // Block size parameter
  p: number; // Parallelization parameter
  dkLen: number; // Desired key length in bytes
}

export async function scrypt(
  password: string,
  salt: string,
  options: ScryptOptions
): Promise<string> {
  return await ExpoScryptModule.scrypt(password, salt, options);
}
