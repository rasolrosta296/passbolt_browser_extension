import KeycloakGroupProvisioningService from "../../service/keycloakSso/keycloakGroupProvisioningService";

export default class KeycloakGroupProvisioningPendingController {
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
      const items = await this.service.findPending();
      this.worker.port.emit(this.requestId, "SUCCESS", { items });
    } catch (error) {
      console.error("Keycloak group-provisioning queue retrieval failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
