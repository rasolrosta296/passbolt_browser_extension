import Keyring from "../../model/keyring";
import CheckPassphraseService from "../crypto/checkPassphraseService";
import AuthVerifyLoginChallengeService from "../auth/authVerifyLoginChallengeService";
import PostLoginService from "../auth/postLoginService";
import PassphraseStorageService from "../session_storage/passphraseStorageService";
import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";
import KeycloakCryptoEnvelopeService from "./keycloakCryptoEnvelopeService";
import KeycloakOidcTabService from "./keycloakOidcTabService";
import { clearBytes } from "./encoding";
import { CRYPTO_SUITE, PROTOCOL_VERSION } from "./cborProtocolV1";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export default class KeycloakCryptoSsoService {
  constructor(apiClientOptions, account) {
    this.account = account;
    this.api = new KeycloakCryptoSsoApiService(apiClientOptions);
    this.gpgAuth = new AuthVerifyLoginChallengeService(apiClientOptions);
  }

  async startEnrollment() {
    const start = await this.api.startEnrollment();
    this.assertStartResponse(start, true);
    await KeycloakOidcTabService.authenticate(start.authorization_url, this.account.domain);
    return {
      enrollment_id: start.enrollment_id,
      identity_id: start.identity_id,
      protocol_version: start.protocol_version,
      crypto_suite: start.crypto_suite,
    };
  }

  async completeEnrollment(start, enrollmentPassphrase) {
    if (typeof enrollmentPassphrase !== "string" || enrollmentPassphrase.length === 0) {
      throw new TypeError("A Passbolt passphrase is required for browser-profile enrollment.");
    }
    this.assertEnrollmentMetadata(start);
    let passphrase = enrollmentPassphrase;
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

  async hasLocalEnrollment() {
    const storageKey = BrowserProfileEnrollmentStorage.storageKey(this.account.domain, this.account.userId);
    const local = await BrowserProfileEnrollmentStorage.get(storageKey);
    if (local === null) {
      return false;
    }
    KeycloakCryptoEnvelopeService.validateLocal(local);
    return (
      local.context.passbolt_origin === new URL(this.account.domain).origin &&
      local.context.user_uuid === this.account.userId &&
      local.context.openpgp_fingerprint === this.account.userKeyFingerprint.toUpperCase()
    );
  }

  async unlink() {
    const response = await this.api.unlinkIdentity();
    const clientEnrollmentUuids = response?.client_enrollment_uuids;
    if (
      !Array.isArray(clientEnrollmentUuids) ||
      clientEnrollmentUuids.some((id) => typeof id !== "string" || !UUID_PATTERN.test(id)) ||
      new Set(clientEnrollmentUuids).size !== clientEnrollmentUuids.length
    ) {
      throw new Error("The API returned an invalid Keycloak unlink result.");
    }
    const storageKey = BrowserProfileEnrollmentStorage.storageKey(this.account.domain, this.account.userId);
    const local = await BrowserProfileEnrollmentStorage.get(storageKey);
    if (local !== null) {
      await BrowserProfileEnrollmentStorage.remove(storageKey);
    }
    return { clientEnrollmentUuids };
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
      await PassphraseStorageService.set(passphrase, 60);
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
    if (enrollment) {
      this.assertEnrollmentMetadata(start);
    }
    if (!enrollment && typeof start.request_id !== "string") {
      throw new Error("The API returned an invalid release request identifier.");
    }
  }

  assertEnrollmentMetadata(start) {
    if (
      !start ||
      typeof start.enrollment_id !== "string" ||
      typeof start.identity_id !== "string" ||
      start.protocol_version !== PROTOCOL_VERSION ||
      start.crypto_suite !== CRYPTO_SUITE
    ) {
      throw new Error("The API returned incomplete or unsupported enrollment metadata.");
    }
  }
}
