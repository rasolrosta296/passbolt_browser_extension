import { v4 as uuidv4 } from "uuid";
import GetPassphraseService from "../passphrase/getPassphraseService";
import { QuickAccessService } from "../ui/quickAccess.service";

/**
 * Obtain an enrollment passphrase in extension-owned Quick Access UI.
 *
 * This deliberately does not call GetPassphraseService#getPassphrase or its
 * remember facilities. The plaintext result remains in the background context.
 */
export default class KeycloakPassphrasePromptService {
  constructor(account) {
    this.getPassphraseService = new GetPassphraseService(account);
  }

  async request() {
    const requestId = uuidv4();
    const parameters = [
      { name: "feature", value: "request-passphrase" },
      { name: "requestId", value: requestId },
    ];
    let response;
    if (QuickAccessService.isAttachedModeAvailable()) {
      const workerId = await QuickAccessService.open(parameters);
      response = await this.getPassphraseService.listenToAttachedQuickaccessPassphraseRequestResponse(
        requestId,
        workerId,
      );
    } else {
      const window = await QuickAccessService.openInDetachedMode(parameters);
      response = await this.getPassphraseService.listenToDetachedQuickaccessPassphraseRequestResponse(
        requestId,
        window,
      );
    }
    let passphrase = response?.passphrase;
    try {
      await this.getPassphraseService.validatePassphrase(passphrase);
      return passphrase;
    } finally {
      if (response && typeof response === "object") {
        response.passphrase = "";
      }
      response = null;
      passphrase = null;
    }
  }
}
