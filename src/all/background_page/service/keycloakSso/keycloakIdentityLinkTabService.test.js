import KeycloakIdentityLinkTabService from "./keycloakIdentityLinkTabService";

const PASSBOLT_ORIGIN = "https://passbolt.example.test";
const TAB_ID = 42;

describe("KeycloakIdentityLinkTabService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    browser.tabs.create.mockResolvedValue({ id: TAB_ID });
    browser.tabs.remove.mockResolvedValue();
  });

  it.each([
    "http://passbolt.example.test",
    "https://user@passbolt.example.test",
    "https://user:password@passbolt.example.test",
  ])("rejects an unsafe Passbolt URL before opening a tab: %s", async (passboltUrl) => {
    await expect(KeycloakIdentityLinkTabService.link(passboltUrl)).rejects.toThrow("The Passbolt URL must use HTTPS.");
    expect(browser.tabs.create).not.toHaveBeenCalled();
  });

  it("opens only the fixed Passbolt link route and accepts only its exact result route", async () => {
    const linking = KeycloakIdentityLinkTabService.link(PASSBOLT_ORIGIN);
    await runPendingPromises();

    expect(browser.tabs.create).toHaveBeenCalledWith({
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/link`,
      active: true,
    });
    browser.tabs.onUpdated.triggers(TAB_ID + 1, { url: `${PASSBOLT_ORIGIN}/auth/keycloak/link/result` });
    browser.tabs.onUpdated.triggers(TAB_ID, { url: "https://attacker.example.test/auth/keycloak/link/result" });
    browser.tabs.onUpdated.triggers(TAB_ID, { url: `${PASSBOLT_ORIGIN}/auth/keycloak/link/result?value=1` });
    browser.tabs.onUpdated.triggers(TAB_ID, { url: `${PASSBOLT_ORIGIN}/auth/keycloak/link/result#value` });
    expect(browser.tabs.onUpdated.removeListener).not.toHaveBeenCalled();

    browser.tabs.onUpdated.triggers(TAB_ID, { url: `${PASSBOLT_ORIGIN}/auth/keycloak/link/result` });

    await expect(linking).resolves.toBeUndefined();
    expect(browser.tabs.onUpdated.removeListener).toHaveBeenCalledTimes(1);
    expect(browser.tabs.onRemoved.removeListener).toHaveBeenCalledTimes(1);
    expect(browser.tabs.remove).toHaveBeenCalledWith(TAB_ID);
  });

  it("rejects the exact fixed failure route", async () => {
    const linking = KeycloakIdentityLinkTabService.link(PASSBOLT_ORIGIN);
    await runPendingPromises();

    browser.tabs.onUpdated.triggers(TAB_ID, { url: `${PASSBOLT_ORIGIN}/auth/keycloak/link/error` });

    await expect(linking).rejects.toThrow("Keycloak identity linking failed.");
    expect(browser.tabs.remove).toHaveBeenCalledWith(TAB_ID);
  });
});

function runPendingPromises() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
