import KeycloakGroupProvisioningService from "../../service/keycloakSso/keycloakGroupProvisioningService";

export default class KeycloakGroupProvisioningCompleteController {
  constructor(worker, requestId, apiClientOptions, account) {
    this.worker = worker;
    this.requestId = requestId;
    this.service = new KeycloakGroupProvisioningService(apiClientOptions, account);
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak group provisioning is restricted to extension-owned Quick Access UI.");
      }
      const result = await this.service.completePending(this.worker);
      this.worker.port.emit(this.requestId, "SUCCESS", result);
    } catch (error) {
      console.error("Keycloak group provisioning failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
