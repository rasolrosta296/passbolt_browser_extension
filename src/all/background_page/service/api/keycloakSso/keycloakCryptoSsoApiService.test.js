import { enableFetchMocks } from "jest-fetch-mock";
import { mockApiResponse } from "passbolt-styleguide/test/mocks/mockApiResponse";
import { defaultApiClientOptions } from "passbolt-styleguide/src/shared/lib/apiClient/apiClientOptions.test.data";
import KeycloakCryptoSsoApiService from "./keycloakCryptoSsoApiService";

describe("KeycloakCryptoSsoApiService", () => {
  beforeEach(() => {
    enableFetchMocks();
    fetch.resetMocks();
  });

  it("retrieves the authenticated identity-link status with a GET request", async () => {
    fetch.doMockOnceIf(/\/auth\/keycloak\/link\/status\.json/, () => mockApiResponse({ linked: true }));
    const service = new KeycloakCryptoSsoApiService(defaultApiClientOptions());

    await expect(service.getIdentityLinkStatus()).resolves.toEqual({ linked: true });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].method).toBe("GET");
  });
});
