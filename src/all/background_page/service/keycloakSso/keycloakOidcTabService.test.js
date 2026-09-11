import KeycloakOidcTabService from "./keycloakOidcTabService";

const AUTHORIZATION_URL =
  "https://keycloak.example.test/realms/passbolt/protocol/openid-connect/auth?client_id=passbolt";
const PASSBOLT_ORIGIN = "https://passbolt.example.test";
const TAB_ID = 42;

describe("KeycloakOidcTabService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    browser.tabs.create.mockResolvedValue({ id: TAB_ID });
    browser.tabs.remove.mockResolvedValue();
  });

  it.each([
    "http://keycloak.example.test/authorize",
    "https://user@keycloak.example.test/authorize",
    "https://user:password@keycloak.example.test/authorize",
  ])("rejects an unsafe authorization URL before opening a tab: %s", async (authorizationUrl) => {
    await expect(KeycloakOidcTabService.authenticate(authorizationUrl, PASSBOLT_ORIGIN)).rejects.toThrow(
      "The OIDC authorization URL must use HTTPS.",
    );
    expect(browser.tabs.create).not.toHaveBeenCalled();
  });

  it("accepts only the exact fixed completion URL on the expected tab", async () => {
    const authentication = KeycloakOidcTabService.authenticate(AUTHORIZATION_URL, PASSBOLT_ORIGIN);
    await runPendingPromises();

    browser.tabs.onUpdated.triggers(TAB_ID + 1, {
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/crypto/complete`,
    });
    browser.tabs.onUpdated.triggers(TAB_ID, {
      url: "https://attacker.example.test/auth/keycloak/crypto/complete",
    });
    browser.tabs.onUpdated.triggers(TAB_ID, {
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/crypto/complete?unexpected=value`,
    });
    browser.tabs.onUpdated.triggers(TAB_ID, {
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/crypto/complete#unexpected`,
    });
    browser.tabs.onUpdated.triggers(TAB_ID, { url: "not a URL" });
    expect(browser.tabs.onUpdated.removeListener).not.toHaveBeenCalled();

    browser.tabs.onUpdated.triggers(TAB_ID, {
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/crypto/complete`,
    });

    await expect(authentication).resolves.toBeUndefined();
    expect(browser.tabs.onUpdated.removeListener).toHaveBeenCalledTimes(1);
    expect(browser.tabs.onRemoved.removeListener).toHaveBeenCalledTimes(1);
    expect(browser.tabs.remove).toHaveBeenCalledWith(TAB_ID);
  });

  it("uses only the exact fixed failure URL", async () => {
    const authentication = KeycloakOidcTabService.authenticate(AUTHORIZATION_URL, PASSBOLT_ORIGIN);
    await runPendingPromises();

    browser.tabs.onUpdated.triggers(TAB_ID, {
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/error.json?unexpected=value`,
    });
    expect(browser.tabs.onUpdated.removeListener).not.toHaveBeenCalled();
    browser.tabs.onUpdated.triggers(TAB_ID, {
      url: `${PASSBOLT_ORIGIN}/auth/keycloak/error.json`,
    });

    await expect(authentication).rejects.toThrow("Keycloak authentication failed.");
    expect(browser.tabs.remove).toHaveBeenCalledWith(TAB_ID);
  });
});

function runPendingPromises() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
