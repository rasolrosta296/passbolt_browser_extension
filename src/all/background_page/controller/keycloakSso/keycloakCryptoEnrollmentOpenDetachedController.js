import { QuickAccessService } from "../../service/ui/quickAccess.service";

export default class KeycloakCryptoEnrollmentOpenDetachedController {
  constructor(worker, requestId) {
    this.worker = worker;
    this.requestId = requestId;
  }

  async _exec() {
    try {
      if (this.worker.name !== "QuickAccess") {
        throw new Error("Keycloak enrollment handoff is restricted to extension-owned Quick Access UI.");
      }
      await QuickAccessService.openInDetachedMode([{ name: "feature", value: "keycloak-sso" }]);
      this.worker.port.emit(this.requestId, "SUCCESS");
    } catch (error) {
      console.error("Keycloak detached enrollment handoff failed.");
      this.worker.port.emit(this.requestId, "ERROR", error);
    }
  }
}
