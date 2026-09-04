import KeycloakCryptoEnrollmentController from "./keycloakCryptoEnrollmentController";
import KeycloakCryptoEnrollmentStartController from "./keycloakCryptoEnrollmentStartController";
import KeycloakCryptoLoginController from "./keycloakCryptoLoginController";
import KeycloakCryptoEnrollmentStatusController from "./keycloakCryptoEnrollmentStatusController";
import KeycloakIdentityUnlinkController from "./keycloakIdentityUnlinkController";
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

  it("rejects browser-profile enrollment completion outside extension-owned Quick Access UI", async () => {
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentController(worker, "request-id", {}, {});

    await controller._exec({}, "dummy-passphrase");

    expect(KeycloakCryptoSsoService.prototype.completeEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("allows browser-profile enrollment completion from extension-owned Quick Access UI", async () => {
    const enrollment = { enrollment_id: "enrollment-id" };
    KeycloakCryptoSsoService.prototype.completeEnrollment.mockResolvedValue(enrollment);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentController(worker, "request-id", {}, {});

    await controller._exec({ enrollment_id: "enrollment-id" }, "dummy-passphrase");

    expect(KeycloakCryptoSsoService.prototype.completeEnrollment).toHaveBeenCalledWith(
      { enrollment_id: "enrollment-id" },
      "dummy-passphrase",
    );
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS", enrollment);
  });

  it("starts fresh OIDC before asking the Quick Access UI for a passphrase", async () => {
    const metadata = { enrollment_id: "enrollment-id" };
    KeycloakCryptoSsoService.prototype.startEnrollment.mockResolvedValue(metadata);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentStartController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.startEnrollment).toHaveBeenCalledTimes(1);
    expect(KeycloakCryptoSsoService.prototype.completeEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS", metadata);
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

  it("returns local enrollment status only to extension-owned Quick Access UI", async () => {
    KeycloakCryptoSsoService.prototype.hasLocalEnrollment.mockResolvedValue(true);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentStatusController(worker, "request-id", {}, {});

    await controller._exec();

    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS", { enrolled: true });
  });

  it("rejects local enrollment status outside extension-owned Quick Access UI", async () => {
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentStatusController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.hasLocalEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("unlinks and cleans up only from extension-owned Quick Access UI", async () => {
    KeycloakCryptoSsoService.prototype.unlink.mockResolvedValue({ clientEnrollmentUuids: [] });
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakIdentityUnlinkController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.unlink).toHaveBeenCalledTimes(1);
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS", { clientEnrollmentUuids: [] });
  });

  it("rejects unlink outside extension-owned Quick Access UI", async () => {
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakIdentityUnlinkController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.unlink).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });
});
