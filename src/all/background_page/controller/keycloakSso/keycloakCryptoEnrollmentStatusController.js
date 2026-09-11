import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";

export default class KeycloakCryptoEnrollmentStatusController {
  constructor(worker, requestId, apiClientOptions, account) {
    this.worker = worker;
    this.requestId = requestId;
    this.service = new KeycloakCryptoSsoService(apiClientOptions, account);
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak enrollment status is restricted to extension-owned Quick Access UI.");
      }
      const status = await this.service.getManagementStatus();
      this.worker.port.emit(this.requestId, "SUCCESS", status);
    } catch (error) {
      console.error("Keycloak browser-profile enrollment status failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
