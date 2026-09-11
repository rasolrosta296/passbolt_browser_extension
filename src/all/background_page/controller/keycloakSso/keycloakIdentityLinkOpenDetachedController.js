import { QuickAccessService } from "../../service/ui/quickAccess.service";

export default class KeycloakIdentityLinkOpenDetachedController {
  constructor(worker, requestId) {
    this.worker = worker;
    this.requestId = requestId;
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak identity-link handoff is restricted to extension-owned Quick Access UI.");
      }
      await QuickAccessService.openInTabMode([{ name: "feature", value: "keycloak-sso" }]);
      this.worker.port.emit(this.requestId, "SUCCESS");
    } catch (error) {
      console.error("Keycloak identity-link tab handoff failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
