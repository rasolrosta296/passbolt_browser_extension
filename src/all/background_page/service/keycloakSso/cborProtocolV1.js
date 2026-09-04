import { decode, encode, rfc8949EncodeOptions } from "cborg";

export const PROTOCOL_VERSION = "passbolt-keycloak-sso-v1";
export const CRYPTO_SUITE = "AES-256-GCM+HPKE-P256-HKDF-SHA256-AES128GCM";
export const CONTEXT_FIELDS = Object.freeze([
  "protocol_version",
  "crypto_suite",
  "passbolt_origin",
  "user_uuid",
  "identity_uuid",
  "enrollment_uuid",
  "client_enrollment_uuid",
  "openpgp_fingerprint",
  "enrollment_public_key_thumbprint",
]);
export const DOMAINS = Object.freeze({
  inner_aad: "passbolt-keycloak-sso-v1/inner-aead",
  outer_aad: "passbolt-keycloak-sso-v1/outer-aead",
  enrollment_transcript: "passbolt-keycloak-sso-v1/enrollment-transcript",
  device_login: "passbolt-keycloak-sso-v1/device-login",
  release_package: "passbolt-keycloak-sso-v1/release-package",
  context_hash: "passbolt-keycloak-sso-v1/context-hash",
});

const encoder = new TextEncoder();
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fingerprintPattern = /^[0-9A-F]{40}$/;
const thumbprintPattern = /^[\w-]{43}$/;
const dnsLabelPattern = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

export function validateContext(context) {
  if (
    context === null ||
    typeof context !== "object" ||
    Array.isArray(context) ||
    Object.getPrototypeOf(context) !== Object.prototype ||
    JSON.stringify(Object.keys(context)) !== JSON.stringify(CONTEXT_FIELDS)
  ) {
    throw new TypeError("Context must contain exactly the ordered version-one fields.");
  }
  for (const field of CONTEXT_FIELDS) {
    if (typeof context[field] !== "string") {
      throw new TypeError(`${field} must be a text string.`);
    }
  }
  if (context.protocol_version !== PROTOCOL_VERSION || context.crypto_suite !== CRYPTO_SUITE) {
    throw new TypeError("Unsupported protocol version or cryptographic suite.");
  }
  const origin = new URL(context.passbolt_origin);
  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash ||
    origin.origin !== context.passbolt_origin ||
    encoder.encode(origin.origin).length > 255 ||
    origin.hostname !== origin.hostname.toLowerCase() ||
    origin.hostname.length > 253 ||
    origin.hostname.split(".").length < 2 ||
    origin.hostname.split(".").some((label) => !dnsLabelPattern.test(label))
  ) {
    throw new TypeError("Passbolt origin must be a canonical absolute HTTPS origin.");
  }
  for (const field of ["user_uuid", "identity_uuid", "enrollment_uuid", "client_enrollment_uuid"]) {
    if (!uuidPattern.test(context[field])) {
      throw new TypeError(`${field} must be a canonical lowercase UUID.`);
    }
  }
  if (
    !fingerprintPattern.test(context.openpgp_fingerprint) ||
    !thumbprintPattern.test(context.enrollment_public_key_thumbprint)
  ) {
    throw new TypeError("Fingerprint or enrollment public-key thumbprint is invalid.");
  }
  return context;
}

export function contextArray(context) {
  validateContext(context);
  return CONTEXT_FIELDS.map((field) => context[field]);
}

export function encodeContext(context) {
  return encode(contextArray(context), rfc8949EncodeOptions);
}

export function encodeBinding(name, context) {
  if (!Object.prototype.hasOwnProperty.call(DOMAINS, name)) {
    throw new TypeError("Unknown protocol domain.");
  }
  return encode([DOMAINS[name], contextArray(context)], rfc8949EncodeOptions);
}

function encodeFixedTranscript(name, context, requestValues) {
  if (
    !Object.prototype.hasOwnProperty.call(DOMAINS, name) ||
    !Array.isArray(requestValues) ||
    requestValues.some((value) => typeof value !== "string" || value === "")
  ) {
    throw new TypeError("Invalid protocol transcript.");
  }
  return encode([[DOMAINS[name], contextArray(context)], requestValues], rfc8949EncodeOptions);
}

export function encodeEnrollmentTranscript(context, clientBlobDigest, serverShareDigest) {
  return encodeFixedTranscript("enrollment_transcript", context, [clientBlobDigest, serverShareDigest]);
}

export function encodeDeviceLoginTranscript(context, clientNonce, hpkeRecipientPublicKey, clientBlobDigest) {
  return encodeFixedTranscript("device_login", context, [clientNonce, hpkeRecipientPublicKey, clientBlobDigest]);
}

export function encodeReleasePackageTranscript(context, clientNonce, hpkeRecipientPublicKey, requestId) {
  return encodeFixedTranscript("release_package", context, [clientNonce, hpkeRecipientPublicKey, requestId]);
}

export function decodeContext(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 2048) {
    throw new TypeError("Encoded context size is invalid.");
  }
  const decoded = decode(bytes, { strict: true, allowIndefinite: false, allowNaN: false, allowInfinity: false });
  if (
    !Array.isArray(decoded) ||
    decoded.length !== CONTEXT_FIELDS.length ||
    decoded.some((value) => typeof value !== "string")
  ) {
    throw new TypeError("Encoded context does not match the fixed array schema.");
  }
  const context = Object.fromEntries(CONTEXT_FIELDS.map((field, index) => [field, decoded[index]]));
  validateContext(context);
  if (!equalBytes(bytes, encodeContext(context))) {
    throw new TypeError("Encoded context is not deterministic.");
  }
  return context;
}

export function decodeEnrollmentTranscript(bytes) {
  return decodeFixedTranscript(bytes, "enrollment_transcript", 2);
}

export function decodeDeviceLoginTranscript(bytes) {
  return decodeFixedTranscript(bytes, "device_login", 3);
}

export function decodeReleasePackageTranscript(bytes) {
  return decodeFixedTranscript(bytes, "release_package", 3);
}

function decodeFixedTranscript(bytes, name, valueCount) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 4096) {
    throw new TypeError("Encoded transcript size is invalid.");
  }
  const decoded = decode(bytes, { strict: true, allowIndefinite: false, allowNaN: false, allowInfinity: false });
  if (
    !Array.isArray(decoded) ||
    decoded.length !== 2 ||
    !Array.isArray(decoded[0]) ||
    decoded[0].length !== 2 ||
    decoded[0][0] !== DOMAINS[name] ||
    !Array.isArray(decoded[0][1]) ||
    !Array.isArray(decoded[1]) ||
    decoded[1].length !== valueCount ||
    decoded[1].some((value) => typeof value !== "string" || value === "")
  ) {
    throw new TypeError("Encoded transcript does not match its fixed schema.");
  }
  const context = Object.fromEntries(CONTEXT_FIELDS.map((field, index) => [field, decoded[0][1][index]]));
  validateContext(context);
  const reencoded = encodeFixedTranscript(name, context, decoded[1]);
  if (!equalBytes(bytes, reencoded)) {
    throw new TypeError("Encoded transcript is not deterministic.");
  }
  return { context, values: decoded[1] };
}

export function equalBytes(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}
