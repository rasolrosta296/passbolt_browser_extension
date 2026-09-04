import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";

export default class KeycloakCryptoLoginController {
  constructor(worker, requestId, apiClientOptions, account) {
    this.worker = worker;
    this.requestId = requestId;
    this.service = new KeycloakCryptoSsoService(apiClientOptions, account);
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak cryptographic login must start from extension-owned Quick Access UI.");
      }
      await this.service.login();
      this.worker.port.emit(this.requestId, "SUCCESS");
    } catch (error) {
      console.error("Keycloak cryptographic login failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
