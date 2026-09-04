import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export default class KeycloakCryptoSsoRotationService {
  constructor(apiClientOptions, account) {
    this.account = account;
    this.api = new KeycloakCryptoSsoApiService(apiClientOptions);
  }

  async revokeServerEnrollments() {
    const response = await this.api.revokeEnrollments();
    const clientEnrollmentUuids = response?.client_enrollment_uuids;
    if (
      !Array.isArray(clientEnrollmentUuids) ||
      clientEnrollmentUuids.some((id) => typeof id !== "string" || !UUID_PATTERN.test(id)) ||
      new Set(clientEnrollmentUuids).size !== clientEnrollmentUuids.length
    ) {
      throw new Error("The API returned an invalid cryptographic enrollment revocation result.");
    }
    return clientEnrollmentUuids;
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
}
