import GetPassphraseService from "../passphrase/getPassphraseService";
import { QuickAccessService } from "../ui/quickAccess.service";
import KeycloakPassphrasePromptService from "./keycloakPassphrasePromptService";

jest.mock("../passphrase/getPassphraseService");
jest.mock("../ui/quickAccess.service");

describe("KeycloakPassphrasePromptService", () => {
  beforeEach(() => {
    QuickAccessService.isAttachedModeAvailable.mockReturnValue(false);
    QuickAccessService.openInDetachedMode.mockResolvedValue({ tabs: [{ id: 42 }] });
    GetPassphraseService.prototype.listenToDetachedQuickaccessPassphraseRequestResponse.mockResolvedValue({
      passphrase: "dummy-passphrase",
      rememberMe: true,
    });
    GetPassphraseService.prototype.validatePassphrase.mockResolvedValue();
  });

  it("uses extension-owned Quick Access and never calls remember storage", async () => {
    const service = new KeycloakPassphrasePromptService({ id: "account" });
    await expect(service.request()).resolves.toBe("dummy-passphrase");
    expect(QuickAccessService.openInDetachedMode).toHaveBeenCalledWith(
      expect.arrayContaining([{ name: "feature", value: "request-passphrase" }]),
    );
    expect(GetPassphraseService.prototype.validatePassphrase).toHaveBeenCalledWith("dummy-passphrase");
    expect(GetPassphraseService.prototype.getPassphrase).not.toHaveBeenCalled();
    expect(GetPassphraseService.prototype.requestPassphrase).not.toHaveBeenCalled();
    expect(GetPassphraseService.prototype.rememberPassphrase).not.toHaveBeenCalled();
  });

  it("does not fall back to a page worker when Quick Access is cancelled", async () => {
    GetPassphraseService.prototype.listenToDetachedQuickaccessPassphraseRequestResponse.mockRejectedValue(
      new Error("cancelled"),
    );
    const service = new KeycloakPassphrasePromptService({ id: "account" });
    await expect(service.request()).rejects.toThrow("cancelled");
    expect(GetPassphraseService.prototype.requestPassphrase).not.toHaveBeenCalled();
  });
});
