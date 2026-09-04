import Keyring from "../../model/keyring";
import CheckPassphraseService from "../crypto/checkPassphraseService";
import AuthVerifyLoginChallengeService from "../auth/authVerifyLoginChallengeService";
import PostLoginService from "../auth/postLoginService";
import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";
import KeycloakCryptoEnvelopeService from "./keycloakCryptoEnvelopeService";
import KeycloakOidcTabService from "./keycloakOidcTabService";
import KeycloakPassphrasePromptService from "./keycloakPassphrasePromptService";
import { clearBytes } from "./encoding";

export default class KeycloakCryptoSsoService {
  constructor(apiClientOptions, account) {
    this.account = account;
    this.api = new KeycloakCryptoSsoApiService(apiClientOptions);
    this.gpgAuth = new AuthVerifyLoginChallengeService(apiClientOptions);
  }

  async enroll() {
    const start = await this.api.startEnrollment();
    this.assertStartResponse(start, true);
    await KeycloakOidcTabService.authenticate(start.authorization_url, this.account.domain);
    let passphrase = await new KeycloakPassphrasePromptService(this.account).request();
    let envelope;
    try {
      await new CheckPassphraseService(new Keyring()).checkPassphrase(passphrase);
      envelope = await KeycloakCryptoEnvelopeService.create(passphrase, this.account, start);
      const registered = await this.api.enroll(envelope.upload);
      if (
        registered?.enrollment_id !== envelope.local.enrollmentId ||
        registered?.client_enrollment_uuid !== envelope.local.clientEnrollmentUuid
      ) {
        throw new Error("The API returned a mismatched enrollment.");
      }
      envelope.local.storageKey = BrowserProfileEnrollmentStorage.storageKey(this.account.domain, this.account.userId);
      await BrowserProfileEnrollmentStorage.save(envelope.local);
      return {
        enrollment_id: envelope.local.enrollmentId,
        client_enrollment_uuid: envelope.local.clientEnrollmentUuid,
      };
    } finally {
      if (envelope?.upload) {
        envelope.upload.server_share = "";
        envelope.upload.openpgp_transcript_signature = "";
      }
      clearBytes(envelope?.rawKs);
      envelope = null;
      passphrase = null;
    }
  }

  async login() {
    const storageKey = BrowserProfileEnrollmentStorage.storageKey(this.account.domain, this.account.userId);
    const local = await BrowserProfileEnrollmentStorage.get(storageKey);
    KeycloakCryptoEnvelopeService.validateLocal(local);
    if (
      local.context.passbolt_origin !== new URL(this.account.domain).origin ||
      local.context.user_uuid !== this.account.userId ||
      local.context.openpgp_fingerprint !== this.account.userKeyFingerprint.toUpperCase()
    ) {
      throw new Error("The browser-profile enrollment does not belong to this account.");
    }
    let prepared;
    let passphrase;
    try {
      prepared = await KeycloakCryptoEnvelopeService.prepareLogin(local);
      const start = await this.api.startLogin(prepared.payload);
      this.assertStartResponse(start, false);
      await KeycloakOidcTabService.authenticate(start.authorization_url, this.account.domain);
      const releaseRequest = await KeycloakCryptoEnvelopeService.releaseRequest(
        local,
        prepared.transient,
        start.request_id,
      );
      const releasePackage = await this.api.release(releaseRequest);
      passphrase = await KeycloakCryptoEnvelopeService.recoverPassphrase(
        local,
        prepared.transient,
        start.request_id,
        releasePackage,
      );
      await new CheckPassphraseService(new Keyring()).checkPassphrase(passphrase);
      await this.gpgAuth.verifyAndValidateLoginChallenge(
        this.account.userKeyFingerprint,
        this.account.userPrivateArmoredKey,
        passphrase,
      );
      await PostLoginService.exec();
    } finally {
      clearBytes(prepared?.transient?.clientNonce);
      clearBytes(prepared?.transient?.hpkePublicKey);
      if (prepared?.payload) {
        prepared.payload.signature = "";
      }
      prepared = null;
      passphrase = null;
    }
  }

  assertStartResponse(start, enrollment) {
    if (
      !start ||
      typeof start.authorization_url !== "string" ||
      new URL(start.authorization_url).protocol !== "https:"
    ) {
      throw new Error("The API returned an invalid Keycloak authorization response.");
    }
    if (enrollment && (typeof start.enrollment_id !== "string" || typeof start.identity_id !== "string")) {
      throw new Error("The API returned incomplete enrollment metadata.");
    }
    if (!enrollment && typeof start.request_id !== "string") {
      throw new Error("The API returned an invalid release request identifier.");
    }
  }
}
