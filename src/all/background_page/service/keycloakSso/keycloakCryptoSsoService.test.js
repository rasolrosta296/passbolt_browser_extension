import AuthVerifyLoginChallengeService from "../auth/authVerifyLoginChallengeService";
import PostLoginService from "../auth/postLoginService";
import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";
import KeycloakCryptoEnvelopeService from "./keycloakCryptoEnvelopeService";
import KeycloakCryptoSsoService from "./keycloakCryptoSsoService";
import KeycloakOidcTabService from "./keycloakOidcTabService";

jest.mock("../../model/keyring");
jest.mock("../crypto/checkPassphraseService");
jest.mock("../auth/authVerifyLoginChallengeService");
jest.mock("../auth/postLoginService");
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
    service = new KeycloakCryptoSsoService({}, account);
    service.api.startLogin.mockResolvedValue({
      authorization_url: "https://keycloak.example.test/authorize",
      request_id: "50000000-0000-4000-8000-000000000005",
    });
    service.api.release.mockResolvedValue({ enc: "enc", ciphertext: "ciphertext", context_hash: "hash" });
    AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge.mockResolvedValue();
    PostLoginService.exec.mockResolvedValue();
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
    expect(PostLoginService.exec).toHaveBeenCalledTimes(1);
    expect(
      AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge.mock.invocationCallOrder[0],
    ).toBeLessThan(PostLoginService.exec.mock.invocationCallOrder[0]);
  });

  it("does not establish authentication when GPGAuth rejects a recovered passphrase", async () => {
    AuthVerifyLoginChallengeService.prototype.verifyAndValidateLoginChallenge.mockRejectedValue(
      new Error("GPGAuth failed"),
    );
    await expect(service.login()).rejects.toThrow("GPGAuth failed");
    expect(service.api.release).toHaveBeenCalled();
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
    expect(PostLoginService.exec).not.toHaveBeenCalled();
  });
});
