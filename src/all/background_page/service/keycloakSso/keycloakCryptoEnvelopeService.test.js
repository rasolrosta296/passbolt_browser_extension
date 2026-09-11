import DecryptPrivateKeyService from "../crypto/decryptPrivateKeyService";
import SignMessageService from "../crypto/signMessageService";
import KeycloakCryptoEnvelopeService from "./keycloakCryptoEnvelopeService";
import { encodeBinding, encodeReleasePackageTranscript } from "./cborProtocolV1";
import * as Encoding from "./encoding";
import { bytesToBase64, clearBytes, sha256Hex } from "./encoding";

jest.mock("../crypto/decryptPrivateKeyService");
jest.mock("../crypto/signMessageService");

const account = {
  domain: "https://passbolt.example.test",
  userId: "10000000-0000-4000-8000-000000000001",
  userKeyFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
  userPrivateArmoredKey: "dummy-encrypted-private-key",
};
const start = {
  identity_id: "20000000-0000-4000-8000-000000000002",
  enrollment_id: "30000000-0000-4000-8000-000000000003",
};

async function releasePackage(local, transient, requestId, rawKs) {
  const recipientPublicKey = await transient.suite.kem.deserializePublicKey(transient.hpkePublicKey);
  const sender = await transient.suite.createSenderContext({
    recipientPublicKey,
    info: encodeBinding("context_hash", transient.context),
  });
  const aad = encodeReleasePackageTranscript(
    transient.context,
    bytesToBase64(transient.clientNonce),
    bytesToBase64(transient.hpkePublicKey),
    requestId,
  );
  return {
    enc: bytesToBase64(sender.enc),
    ciphertext: bytesToBase64(await sender.seal(rawKs, aad)),
    context_hash: await sha256Hex(encodeBinding("context_hash", transient.context)),
  };
}

describe("KeycloakCryptoEnvelopeService", () => {
  beforeEach(() => {
    DecryptPrivateKeyService.decryptArmoredKey.mockResolvedValue({ privateKey: true });
    SignMessageService.signClearMessage.mockResolvedValue("dummy-openpgp-clear-signature");
  });

  afterEach(() => jest.restoreAllMocks());

  it("creates fresh non-extractable profile keys and an interoperable envelope", async () => {
    const first = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const second = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, {
      ...start,
      enrollment_id: "50000000-0000-4000-8000-000000000005",
    });
    expect(first.local.kd.extractable).toBe(false);
    expect(first.local.signingPrivateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", first.local.kd)).rejects.toThrow();
    await expect(crypto.subtle.exportKey("pkcs8", first.local.signingPrivateKey)).rejects.toThrow();
    expect(first.local.clientEnrollmentUuid).not.toBe(second.local.clientEnrollmentUuid);
    expect(bytesToBase64(first.rawKs)).not.toBe(bytesToBase64(second.rawKs));

    const prepared = await KeycloakCryptoEnvelopeService.prepareLogin(first.local);
    const requestId = "60000000-0000-4000-8000-000000000006";
    const released = await releasePackage(first.local, prepared.transient, requestId, first.rawKs);
    await expect(
      KeycloakCryptoEnvelopeService.recoverPassphrase(first.local, prepared.transient, requestId, released),
    ).resolves.toBe("dummy-passphrase");
    clearBytes(first.rawKs);
    clearBytes(second.rawKs);
  });

  it.each(["ciphertext", "enc", "context_hash"])("rejects a modified %s", async (field) => {
    const envelope = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const prepared = await KeycloakCryptoEnvelopeService.prepareLogin(envelope.local);
    const requestId = "60000000-0000-4000-8000-000000000006";
    const released = await releasePackage(envelope.local, prepared.transient, requestId, envelope.rawKs);
    released[field] = `${released[field].slice(0, -1)}${released[field].endsWith("A") ? "B" : "A"}`;
    await expect(
      KeycloakCryptoEnvelopeService.recoverPassphrase(envelope.local, prepared.transient, requestId, released),
    ).rejects.toThrow();
    clearBytes(envelope.rawKs);
  });

  it("rejects local metadata and cross-user substitution", async () => {
    const envelope = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    envelope.local.context = {
      ...envelope.local.context,
      user_uuid: "70000000-0000-4000-8000-000000000007",
    };
    await expect(KeycloakCryptoEnvelopeService.prepareLogin(envelope.local)).rejects.toThrow(
      "local enrollment metadata",
    );
    clearBytes(envelope.rawKs);
  });

  it("clears all mutable secret bytes when enrollment construction fails after exporting KS", async () => {
    const clearBytesSpy = jest.spyOn(Encoding, "clearBytes");
    SignMessageService.signClearMessage.mockRejectedValue(new Error("signature failed"));

    await expect(KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start)).rejects.toThrow(
      "signature failed",
    );

    const clearedBytes = clearBytesSpy.mock.calls
      .map(([bytes]) => bytes)
      .filter((bytes) => bytes instanceof Uint8Array);
    expect(clearedBytes.some((bytes) => bytes.length === new TextEncoder().encode("dummy-passphrase").length)).toBe(
      true,
    );
    expect(clearedBytes.filter((bytes) => bytes.length === 32)).toHaveLength(2);
    expect(clearedBytes.every((bytes) => bytes.every((value) => value === 0))).toBe(true);
  });

  it("rejects profile keys with the wrong algorithm or usage", async () => {
    const envelope = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const invalidKd = { ...envelope.local, kd: envelope.local.signingPrivateKey };
    const invalidSigningKey = { ...envelope.local, signingPrivateKey: envelope.local.kd };

    expect(() => KeycloakCryptoEnvelopeService.validateLocal(invalidKd)).toThrow(
      "browser-profile enrollment is missing or invalid",
    );
    expect(() => KeycloakCryptoEnvelopeService.validateLocal(invalidSigningKey)).toThrow(
      "browser-profile enrollment is missing or invalid",
    );
    clearBytes(envelope.rawKs);
  });

  it("rejects a server share released for a different browser-profile enrollment", async () => {
    const first = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const second = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, {
      ...start,
      enrollment_id: "50000000-0000-4000-8000-000000000005",
    });
    const prepared = await KeycloakCryptoEnvelopeService.prepareLogin(first.local);
    const requestId = "60000000-0000-4000-8000-000000000006";
    const released = await releasePackage(first.local, prepared.transient, requestId, second.rawKs);

    await expect(
      KeycloakCryptoEnvelopeService.recoverPassphrase(first.local, prepared.transient, requestId, released),
    ).rejects.toThrow();
    clearBytes(first.rawKs);
    clearBytes(second.rawKs);
  });

  it("rejects a substituted KD", async () => {
    const first = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const second = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, {
      ...start,
      enrollment_id: "50000000-0000-4000-8000-000000000005",
    });
    const substituted = { ...first.local, kd: second.local.kd };
    const prepared = await KeycloakCryptoEnvelopeService.prepareLogin(substituted);
    const requestId = "60000000-0000-4000-8000-000000000006";
    const released = await releasePackage(substituted, prepared.transient, requestId, first.rawKs);

    await expect(
      KeycloakCryptoEnvelopeService.recoverPassphrase(substituted, prepared.transient, requestId, released),
    ).rejects.toThrow();
    clearBytes(first.rawKs);
    clearBytes(second.rawKs);
  });

  it.each(["innerIv", "outerIv"])("rejects a modified %s", async (field) => {
    const envelope = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const prepared = await KeycloakCryptoEnvelopeService.prepareLogin(envelope.local);
    const requestId = "60000000-0000-4000-8000-000000000006";
    const released = await releasePackage(envelope.local, prepared.transient, requestId, envelope.rawKs);
    const local = {
      ...envelope.local,
      [field]: `${envelope.local[field].slice(0, -1)}${envelope.local[field].endsWith("A") ? "B" : "A"}`,
    };

    await expect(
      KeycloakCryptoEnvelopeService.recoverPassphrase(local, prepared.transient, requestId, released),
    ).rejects.toThrow();
    clearBytes(envelope.rawKs);
  });

  it("rejects a release package bound to another request", async () => {
    const envelope = await KeycloakCryptoEnvelopeService.create("dummy-passphrase", account, start);
    const prepared = await KeycloakCryptoEnvelopeService.prepareLogin(envelope.local);
    const requestId = "60000000-0000-4000-8000-000000000006";
    const released = await releasePackage(envelope.local, prepared.transient, requestId, envelope.rawKs);

    await expect(
      KeycloakCryptoEnvelopeService.recoverPassphrase(
        envelope.local,
        prepared.transient,
        "70000000-0000-4000-8000-000000000007",
        released,
      ),
    ).rejects.toThrow();
    clearBytes(envelope.rawKs);
  });
});
