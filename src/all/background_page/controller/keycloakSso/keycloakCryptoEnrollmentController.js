import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";

export default class KeycloakCryptoEnrollmentController {
  constructor(worker, requestId, apiClientOptions, account) {
    this.worker = worker;
    this.requestId = requestId;
    this.service = new KeycloakCryptoSsoService(apiClientOptions, account);
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak browser-profile enrollment must start from extension-owned Quick Access UI.");
      }
      const enrollment = await this.service.enroll();
      this.worker.port.emit(this.requestId, "SUCCESS", enrollment);
    } catch (error) {
      console.error("Keycloak browser-profile enrollment failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
