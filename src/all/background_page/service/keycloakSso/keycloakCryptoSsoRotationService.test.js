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
  const rotationCapability = "A".repeat(43);
  let service;

  beforeEach(() => {
    jest.clearAllMocks();
    BrowserProfileEnrollmentStorage.storageKey.mockReturnValue("profile-storage-key");
    service = new KeycloakCryptoSsoRotationService({}, account);
  });

  it("accepts only the minimal validated rotation barrier result", async () => {
    KeycloakCryptoSsoApiService.prototype.startPassphraseRotation.mockResolvedValue({
      rotation_capability: rotationCapability,
      client_enrollment_uuids: [clientEnrollmentUuid],
    });

    await expect(service.begin()).resolves.toEqual({
      capability: rotationCapability,
      clientEnrollmentUuids: [clientEnrollmentUuid],
    });
    expect(KeycloakCryptoSsoApiService.prototype.startPassphraseRotation).toHaveBeenCalledTimes(1);
  });

  it.each([
    null,
    {},
    { rotation_capability: "short", client_enrollment_uuids: [] },
    { rotation_capability: rotationCapability },
    { client_enrollment_uuids: "not-an-array" },
    { rotation_capability: rotationCapability, client_enrollment_uuids: ["not-a-uuid"] },
    { rotation_capability: rotationCapability, client_enrollment_uuids: [clientEnrollmentUuid, clientEnrollmentUuid] },
  ])("fails closed on malformed barrier response %#", async (response) => {
    KeycloakCryptoSsoApiService.prototype.startPassphraseRotation.mockResolvedValue(response);

    await expect(service.begin()).rejects.toThrow("The API returned an invalid passphrase-rotation barrier result.");
  });

  it("completes and fails a barrier only with a validated capability", async () => {
    await service.complete(rotationCapability);
    await service.fail(rotationCapability);

    expect(KeycloakCryptoSsoApiService.prototype.completePassphraseRotation).toHaveBeenCalledWith(rotationCapability);
    expect(KeycloakCryptoSsoApiService.prototype.failPassphraseRotation).toHaveBeenCalledWith(rotationCapability);
    await expect(service.complete("invalid")).rejects.toThrow("The passphrase-rotation capability is invalid.");
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

  it("propagates local cleanup failure without starting another barrier", async () => {
    BrowserProfileEnrollmentStorage.get.mockResolvedValue({ clientEnrollmentUuid });
    BrowserProfileEnrollmentStorage.remove.mockRejectedValue(new Error("IndexedDB cleanup failed"));

    await expect(service.removeLocalEnrollments([clientEnrollmentUuid])).rejects.toThrow("IndexedDB cleanup failed");
    expect(KeycloakCryptoSsoApiService.prototype.startPassphraseRotation).not.toHaveBeenCalled();
  });
});
