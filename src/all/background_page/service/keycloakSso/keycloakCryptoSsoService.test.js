import AuthVerifyLoginChallengeService from "../auth/authVerifyLoginChallengeService";
import PostLoginService from "../auth/postLoginService";
import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";
import KeycloakCryptoEnvelopeService from "./keycloakCryptoEnvelopeService";
import KeycloakCryptoSsoService from "./keycloakCryptoSsoService";
import KeycloakOidcTabService from "./keycloakOidcTabService";
import CheckPassphraseService from "../crypto/checkPassphraseService";
import PassphraseStorageService from "../session_storage/passphraseStorageService";

jest.mock("../../model/keyring");
jest.mock("../crypto/checkPassphraseService");
jest.mock("../auth/authVerifyLoginChallengeService");
jest.mock("../auth/postLoginService");
jest.mock("../session_storage/passphraseStorageService");
jest.mock("../api/keycloakSso/keycloakCryptoSsoApiService");
jest.mock("./browserProfileEnrollmentStorage");
jest.mock("./keycloakCryptoEnvelopeService");
jest.mock("./keycloakOidcTabService");

const account = {
  domain: "https://passbolt.example.test",
  userId: "10000000-0000-4000-8000-000000000001",
  userKeyFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
  userPrivateArmoredKey: "dummy-encrypted-private-key",
};

describe("KeycloakCryptoSsoService authentication boundary", () => {
  let service;
  let local;

  beforeEach(() => {
    jest.clearAllMocks();
    local = {
      context: {
        passbolt_origin: account.domain,
        user_uuid: account.userId,
        openpgp_fingerprint: account.userKeyFingerprint,
      },
    };
    BrowserProfileEnrollmentStorage.storageKey.mockReturnValue("profile-key");
    BrowserProfileEnrollmentStorage.get.mockResolvedValue(local);
    KeycloakCryptoEnvelopeService.validateLocal.mockImplementation(() => undefined);
    KeycloakCryptoEnvelopeService.prepareLogin.mockResolvedValue({ payload: {}, transient: {} });
    KeycloakCryptoEnvelopeService.releaseRequest.mockResolvedValue({ request_id: "request", signature: "sig" });
    KeycloakCryptoEnvelopeService.recoverPassphrase.mockResolvedValue("dummy-passphrase");
    KeycloakOidcTabService.authenticate.mockResolvedValue();
    CheckPassphraseService.prototype.checkPassphrase.mockResolvedValue();
    service = new KeycloakCryptoSsoService({}, account);
    service.api.startLogin.mockResolvedValue({
      authorization_url: "https://keycloak.example.test/authorize",
      request_id: "50000000-0000-4000-8000-000000000005",
    });
    service.api.release.mockResolvedValue({ enc: "enc", ciphertext: "ciphertext", context_hash: "hash" });
    AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge.mockResolvedValue();
    PassphraseStorageService.set.mockResolvedValue();
    PostLoginService.exec.mockResolvedValue();
  });

  it("completes fresh OIDC before returning enrollment metadata to the passphrase UI", async () => {
    service.api.startEnrollment.mockResolvedValue({
      authorization_url: "https://keycloak.example.test/authorize",
      enrollment_id: "20000000-0000-4000-8000-000000000002",
      identity_id: "30000000-0000-4000-8000-000000000003",
      protocol_version: "passbolt-keycloak-sso-v1",
      crypto_suite: "AES-256-GCM+HPKE-P256-HKDF-SHA256-AES128GCM",
    });

    const result = await service.startEnrollment();

    expect(KeycloakOidcTabService.authenticate).toHaveBeenCalledTimes(1);
    expect(CheckPassphraseService.prototype.checkPassphrase).not.toHaveBeenCalled();
    expect(result).toEqual({
      enrollment_id: "20000000-0000-4000-8000-000000000002",
      identity_id: "30000000-0000-4000-8000-000000000003",
      protocol_version: "passbolt-keycloak-sso-v1",
      crypto_suite: "AES-256-GCM+HPKE-P256-HKDF-SHA256-AES128GCM",
    });
  });

  it("uses the Quick Access passphrase only for local enrollment completion", async () => {
    const metadata = {
      enrollment_id: "20000000-0000-4000-8000-000000000002",
      identity_id: "30000000-0000-4000-8000-000000000003",
      protocol_version: "passbolt-keycloak-sso-v1",
      crypto_suite: "AES-256-GCM+HPKE-P256-HKDF-SHA256-AES128GCM",
    };
    const saved = { enrollmentId: metadata.enrollment_id, clientEnrollmentUuid: "client-id" };
    KeycloakCryptoEnvelopeService.create.mockResolvedValue({
      upload: { server_share: "dummy", openpgp_transcript_signature: "dummy" },
      local: saved,
      rawKs: new Uint8Array(32),
    });
    service.api.enroll.mockResolvedValue({
      enrollment_id: metadata.enrollment_id,
      client_enrollment_uuid: "client-id",
    });

    await service.completeEnrollment(metadata, "dummy-passphrase");

    expect(CheckPassphraseService.prototype.checkPassphrase).toHaveBeenCalledWith("dummy-passphrase");
    expect(KeycloakCryptoEnvelopeService.create).toHaveBeenCalledWith("dummy-passphrase", account, metadata);
    expect(KeycloakOidcTabService.authenticate).not.toHaveBeenCalled();
    expect(BrowserProfileEnrollmentStorage.save).toHaveBeenCalledWith(saved);
    expect(PassphraseStorageService.set).not.toHaveBeenCalled();
    expect(saved).not.toHaveProperty("passphrase");
  });

  it("establishes authentication only after unchanged GPGAuth succeeds", async () => {
    await service.login();
    expect(KeycloakOidcTabService.authenticate).toHaveBeenCalled();
    expect(service.api.release).toHaveBeenCalled();
    expect(AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge).toHaveBeenCalledWith(
      account.userKeyFingerprint,
      account.userPrivateArmoredKey,
      "dummy-passphrase",
    );
    expect(PassphraseStorageService.set).toHaveBeenCalledWith("dummy-passphrase", 60);
    expect(PostLoginService.exec).toHaveBeenCalledTimes(1);
    const gpgAuthOrder =
      AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge.mock.invocationCallOrder[0];
    const passphraseStorageOrder = PassphraseStorageService.set.mock.invocationCallOrder[0];
    const postLoginOrder = PostLoginService.exec.mock.invocationCallOrder[0];
    expect(gpgAuthOrder).toBeLessThan(passphraseStorageOrder);
    expect(passphraseStorageOrder).toBeLessThan(postLoginOrder);
  });

  it("does not establish authentication when GPGAuth rejects a recovered passphrase", async () => {
    AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge.mockRejectedValue(
      new Error("GPGAuth failed"),
    );
    await expect(service.login()).rejects.toThrow("GPGAuth failed");
    expect(service.api.release).toHaveBeenCalled();
    expect(PassphraseStorageService.set).not.toHaveBeenCalled();
    expect(PostLoginService.exec).not.toHaveBeenCalled();
  });

  it.each([
    [
      "profile preparation",
      () => KeycloakCryptoEnvelopeService.prepareLogin.mockRejectedValue(new Error("prepare failed")),
    ],
    [
      "login transaction start",
      (currentService) => currentService.api.startLogin.mockRejectedValue(new Error("start failed")),
    ],
    [
      "fresh OIDC authentication",
      () => KeycloakOidcTabService.authenticate.mockRejectedValue(new Error("OIDC failed")),
    ],
    [
      "release-request creation",
      () => KeycloakCryptoEnvelopeService.releaseRequest.mockRejectedValue(new Error("release request failed")),
    ],
    [
      "server-share release",
      (currentService) => currentService.api.release.mockRejectedValue(new Error("release failed")),
    ],
    [
      "passphrase recovery",
      () => KeycloakCryptoEnvelopeService.recoverPassphrase.mockRejectedValue(new Error("recovery failed")),
    ],
    [
      "recovered-passphrase validation",
      () => CheckPassphraseService.prototype.checkPassphrase.mockRejectedValue(new Error("check failed")),
    ],
  ])("does not store a passphrase or run post-login when %s fails", async (description, arrangeFailure) => {
    arrangeFailure(service);

    await expect(service.login()).rejects.toThrow();

    expect(PassphraseStorageService.set).not.toHaveBeenCalled();
    expect(PostLoginService.exec).not.toHaveBeenCalled();
  });

  it("does not run post-login if the standard short-lived passphrase storage write fails", async () => {
    PassphraseStorageService.set.mockRejectedValue(new Error("storage failed"));

    await expect(service.login()).rejects.toThrow("storage failed");

    expect(AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge).toHaveBeenCalledTimes(1);
    expect(PostLoginService.exec).not.toHaveBeenCalled();
  });

  it("does not begin OIDC when profile cryptographic material is unavailable", async () => {
    KeycloakCryptoEnvelopeService.validateLocal.mockImplementation(() => {
      throw new Error("KD missing");
    });
    await expect(service.login()).rejects.toThrow("KD missing");
    expect(service.api.startLogin).not.toHaveBeenCalled();
    expect(KeycloakOidcTabService.authenticate).not.toHaveBeenCalled();
    expect(AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge).not.toHaveBeenCalled();
    expect(PassphraseStorageService.set).not.toHaveBeenCalled();
    expect(PostLoginService.exec).not.toHaveBeenCalled();
  });

  it("reports only a valid enrollment belonging to the current account", async () => {
    await expect(service.hasLocalEnrollment()).resolves.toBe(true);
    local.context.user_uuid = "20000000-0000-4000-8000-000000000002";
    await expect(service.hasLocalEnrollment()).resolves.toBe(false);
  });

  it("reports no local enrollment without beginning OIDC", async () => {
    BrowserProfileEnrollmentStorage.get.mockResolvedValue(null);
    await expect(service.hasLocalEnrollment()).resolves.toBe(false);
    expect(service.api.startLogin).not.toHaveBeenCalled();
  });

  it("combines server identity-link status with local browser-profile enrollment status", async () => {
    service.api.getIdentityLinkStatus.mockResolvedValue({ linked: true });

    await expect(service.getManagementStatus()).resolves.toEqual({ linked: true, enrolled: true });

    service.api.getIdentityLinkStatus.mockResolvedValue({ linked: false });
    await expect(service.getManagementStatus()).resolves.toEqual({ linked: false, enrolled: false });
  });

  it("rejects malformed server identity-link status", async () => {
    service.api.getIdentityLinkStatus.mockResolvedValue({ linked: "true" });

    await expect(service.getManagementStatus()).rejects.toThrow(
      "The API returned an invalid Keycloak identity-link status.",
    );
  });

  it("unlinks on the server before deleting the local enrollment", async () => {
    const clientEnrollmentUuid = "20000000-0000-4000-8000-000000000002";
    local.clientEnrollmentUuid = clientEnrollmentUuid;
    service.api.unlinkIdentity.mockResolvedValue({ client_enrollment_uuids: [clientEnrollmentUuid] });

    await expect(service.unlink()).resolves.toEqual({ clientEnrollmentUuids: [clientEnrollmentUuid] });

    expect(service.api.unlinkIdentity).toHaveBeenCalledTimes(1);
    expect(BrowserProfileEnrollmentStorage.remove).toHaveBeenCalledWith("profile-key");
    expect(service.api.unlinkIdentity.mock.invocationCallOrder[0]).toBeLessThan(
      BrowserProfileEnrollmentStorage.remove.mock.invocationCallOrder[0],
    );
  });

  it("deletes orphaned local enrollment after a valid empty server unlink result", async () => {
    service.api.unlinkIdentity.mockResolvedValue({ client_enrollment_uuids: [] });

    await expect(service.unlink()).resolves.toEqual({ clientEnrollmentUuids: [] });

    expect(BrowserProfileEnrollmentStorage.remove).toHaveBeenCalledWith("profile-key");
  });

  it("fails closed on a malformed unlink response and retains local state", async () => {
    service.api.unlinkIdentity.mockResolvedValue({ client_enrollment_uuids: ["invalid"] });
    await expect(service.unlink()).rejects.toThrow("The API returned an invalid Keycloak unlink result.");
    expect(BrowserProfileEnrollmentStorage.remove).not.toHaveBeenCalled();
  });
});
