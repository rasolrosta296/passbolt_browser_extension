import KeycloakIdentityLinkTabService from "../../service/keycloakSso/keycloakIdentityLinkTabService";

export default class KeycloakIdentityLinkController {
  constructor(worker, requestId, account) {
    this.worker = worker;
    this.requestId = requestId;
    this.account = account;
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak identity linking is restricted to extension-owned Quick Access UI.");
      }
      await KeycloakIdentityLinkTabService.link(this.account.domain);
      this.worker.port.emit(this.requestId, "SUCCESS");
    } catch (error) {
      console.error("Keycloak identity linking failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
