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

  it("retrieves the authenticated manager group-provisioning queue with GET", async () => {
    fetch.doMockOnceIf(/\/auth\/keycloak\/provisioning\/groups\/pending\.json/, () => mockApiResponse({ items: [] }));
    const service = new KeycloakCryptoSsoApiService(defaultApiClientOptions());

    await expect(service.getPendingGroupMemberships()).resolves.toEqual({ items: [] });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].method).toBe("GET");
  });

  it("completes a manager group-provisioning queue item with POST", async () => {
    const membershipId = "8d020e76-4951-58d2-b68e-99e2fc1053f8";
    fetch.doMockOnceIf(new RegExp(`/auth/keycloak/provisioning/groups/complete/${membershipId}\\.json`), () =>
      mockApiResponse({}),
    );
    const service = new KeycloakCryptoSsoApiService(defaultApiClientOptions());

    await expect(service.completePendingGroupMembership(membershipId)).resolves.toEqual({});

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0][1].method).toBe("POST");
  });
});
