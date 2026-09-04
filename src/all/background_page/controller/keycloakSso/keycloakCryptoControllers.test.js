import KeycloakCryptoEnrollmentController from "./keycloakCryptoEnrollmentController";
import KeycloakCryptoLoginController from "./keycloakCryptoLoginController";
import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";

jest.mock("../../service/keycloakSso/keycloakCryptoSsoService");

describe("Keycloak cryptographic SSO controllers", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    console.error.mockRestore();
  });

  it("rejects browser-profile enrollment outside extension-owned Quick Access UI", async () => {
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.enroll).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("allows browser-profile enrollment from extension-owned Quick Access UI", async () => {
    const enrollment = { enrollment_id: "enrollment-id" };
    KeycloakCryptoSsoService.prototype.enroll.mockResolvedValue(enrollment);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.enroll).toHaveBeenCalledTimes(1);
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS", enrollment);
  });

  it("rejects cryptographic login outside extension-owned Quick Access UI", async () => {
    const worker = { name: "Auth", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("allows cryptographic login from extension-owned Quick Access UI", async () => {
    KeycloakCryptoSsoService.prototype.login.mockResolvedValue(undefined);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).toHaveBeenCalledTimes(1);
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
  });
});
