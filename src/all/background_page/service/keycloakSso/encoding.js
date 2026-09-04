export const bytesToBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

export const base64ToBytes = (value) => {
  if (typeof value !== "string" || value === "") {
    throw new TypeError("Expected non-empty base64.");
  }
  const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  if (bytesToBase64(bytes) !== value) {
    throw new TypeError("Expected canonical base64.");
  }
  return bytes;
};

export const bytesToBase64Url = (bytes) =>
  bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

export const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

export const sha256Hex = async (bytes) =>
  [...(await sha256(bytes))].map((value) => value.toString(16).padStart(2, "0")).join("");

export function clearBytes(bytes) {
  if (bytes instanceof Uint8Array) {
    bytes.fill(0);
  }
}
