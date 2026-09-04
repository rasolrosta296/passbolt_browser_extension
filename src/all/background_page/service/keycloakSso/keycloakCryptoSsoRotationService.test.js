import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";
import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import KeycloakCryptoSsoRotationService from "./keycloakCryptoSsoRotationService";

jest.mock("../api/keycloakSso/keycloakCryptoSsoApiService");
jest.mock("./browserProfileEnrollmentStorage");

describe("KeycloakCryptoSsoRotationService", () => {
  const account = {
    domain: "https://passbolt.example.test",
    userId: "10000000-0000-4000-8000-000000000001",
  };
  const clientEnrollmentUuid = "20000000-0000-4000-8000-000000000002";
  let service;

  beforeEach(() => {
    jest.clearAllMocks();
    BrowserProfileEnrollmentStorage.storageKey.mockReturnValue("profile-storage-key");
    service = new KeycloakCryptoSsoRotationService({}, account);
  });

  it("accepts only the minimal validated server revocation result", async () => {
    KeycloakCryptoSsoApiService.prototype.revokeEnrollments.mockResolvedValue({
      client_enrollment_uuids: [clientEnrollmentUuid],
    });

    await expect(service.revokeServerEnrollments()).resolves.toEqual([clientEnrollmentUuid]);
    expect(KeycloakCryptoSsoApiService.prototype.revokeEnrollments).toHaveBeenCalledTimes(1);
  });

  it.each([
    null,
    {},
    { client_enrollment_uuids: "not-an-array" },
    { client_enrollment_uuids: ["not-a-uuid"] },
    { client_enrollment_uuids: [clientEnrollmentUuid, clientEnrollmentUuid] },
  ])("fails closed on malformed revocation response %#", async (response) => {
    KeycloakCryptoSsoApiService.prototype.revokeEnrollments.mockResolvedValue(response);

    await expect(service.revokeServerEnrollments()).rejects.toThrow(
      "The API returned an invalid cryptographic enrollment revocation result.",
    );
  });

  it("removes the matching local browser-profile enrollment", async () => {
    BrowserProfileEnrollmentStorage.get.mockResolvedValue({ clientEnrollmentUuid });

    await service.removeLocalEnrollments([clientEnrollmentUuid]);

    expect(BrowserProfileEnrollmentStorage.get).toHaveBeenCalledWith("profile-storage-key");
    expect(BrowserProfileEnrollmentStorage.remove).toHaveBeenCalledWith("profile-storage-key");
  });

  it("does not remove a different local enrollment", async () => {
    BrowserProfileEnrollmentStorage.get.mockResolvedValue({
      clientEnrollmentUuid: "30000000-0000-4000-8000-000000000003",
    });

    await service.removeLocalEnrollments([clientEnrollmentUuid]);

    expect(BrowserProfileEnrollmentStorage.remove).not.toHaveBeenCalled();
  });

  it("does not open IndexedDB when the user has no server enrollment", async () => {
    await service.removeLocalEnrollments([]);

    expect(BrowserProfileEnrollmentStorage.get).not.toHaveBeenCalled();
    expect(BrowserProfileEnrollmentStorage.remove).not.toHaveBeenCalled();
  });

  it("propagates local cleanup failure without contacting the server again", async () => {
    BrowserProfileEnrollmentStorage.get.mockResolvedValue({ clientEnrollmentUuid });
    BrowserProfileEnrollmentStorage.remove.mockRejectedValue(new Error("IndexedDB cleanup failed"));

    await expect(service.removeLocalEnrollments([clientEnrollmentUuid])).rejects.toThrow("IndexedDB cleanup failed");
    expect(KeycloakCryptoSsoApiService.prototype.revokeEnrollments).not.toHaveBeenCalled();
  });
});
