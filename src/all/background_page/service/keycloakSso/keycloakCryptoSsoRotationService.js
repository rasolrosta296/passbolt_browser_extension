import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ROTATION_CAPABILITY_PATTERN = /^[\w-]{43}$/;

export default class KeycloakCryptoSsoRotationService {
  constructor(apiClientOptions, account) {
    this.account = account;
    this.api = new KeycloakCryptoSsoApiService(apiClientOptions);
  }

  async begin() {
    const response = await this.api.startPassphraseRotation();
    const clientEnrollmentUuids = response?.client_enrollment_uuids;
    if (
      typeof response?.rotation_capability !== "string" ||
      !ROTATION_CAPABILITY_PATTERN.test(response.rotation_capability) ||
      !Array.isArray(clientEnrollmentUuids) ||
      clientEnrollmentUuids.some((id) => typeof id !== "string" || !UUID_PATTERN.test(id)) ||
      new Set(clientEnrollmentUuids).size !== clientEnrollmentUuids.length
    ) {
      throw new Error("The API returned an invalid passphrase-rotation barrier result.");
    }
    return {
      capability: response.rotation_capability,
      clientEnrollmentUuids,
    };
  }

  async complete(rotationCapability) {
    this.assertCapability(rotationCapability);
    await this.api.completePassphraseRotation(rotationCapability);
  }

  async fail(rotationCapability) {
    this.assertCapability(rotationCapability);
    await this.api.failPassphraseRotation(rotationCapability);
  }

  async removeLocalEnrollments(clientEnrollmentUuids) {
    if (clientEnrollmentUuids.length === 0) {
      return;
    }
    const storageKey = BrowserProfileEnrollmentStorage.storageKey(this.account.domain, this.account.userId);
    const local = await BrowserProfileEnrollmentStorage.get(storageKey);
    if (local !== null && clientEnrollmentUuids.includes(local.clientEnrollmentUuid)) {
      await BrowserProfileEnrollmentStorage.remove(storageKey);
    }
  }

  assertCapability(rotationCapability) {
    if (typeof rotationCapability !== "string" || !ROTATION_CAPABILITY_PATTERN.test(rotationCapability)) {
      throw new Error("The passphrase-rotation capability is invalid.");
    }
  }
}
