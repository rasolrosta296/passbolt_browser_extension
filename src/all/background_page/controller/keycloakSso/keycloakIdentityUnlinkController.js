import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";

export default class KeycloakIdentityUnlinkController {
  constructor(worker, requestId, apiClientOptions, account) {
    this.worker = worker;
    this.requestId = requestId;
    this.service = new KeycloakCryptoSsoService(apiClientOptions, account);
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak unlink is restricted to extension-owned Quick Access UI.");
      }
      const result = await this.service.unlink();
      this.worker.port.emit(this.requestId, "SUCCESS", result);
    } catch (error) {
      console.error("Keycloak identity unlink failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
