import KeycloakCryptoEnrollmentController from "./keycloakCryptoEnrollmentController";
import KeycloakCryptoEnrollmentOpenDetachedController from "./keycloakCryptoEnrollmentOpenDetachedController";
import KeycloakCryptoEnrollmentStartController from "./keycloakCryptoEnrollmentStartController";
import KeycloakCryptoLoginController from "./keycloakCryptoLoginController";
import KeycloakCryptoLoginOpenDetachedController from "./keycloakCryptoLoginOpenDetachedController";
import KeycloakCryptoEnrollmentStatusController from "./keycloakCryptoEnrollmentStatusController";
import KeycloakIdentityUnlinkController from "./keycloakIdentityUnlinkController";
import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";
import { QuickAccessService } from "../../service/ui/quickAccess.service";

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

  it("opens a Keycloak enrollment Quick Access in detached mode without starting OIDC", async () => {
    const openInDetachedMode = jest.spyOn(QuickAccessService, "openInDetachedMode").mockResolvedValue({ id: 42 });
    const open = jest.spyOn(QuickAccessService, "open");
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInDetachedMode).toHaveBeenCalledWith([{ name: "feature", value: "keycloak-sso" }]);
    expect(open).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoService.prototype.startEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
    openInDetachedMode.mockRestore();
    open.mockRestore();
  });

  it("rejects detached Keycloak enrollment handoff outside Quick Access", async () => {
    const openInDetachedMode = jest.spyOn(QuickAccessService, "openInDetachedMode").mockResolvedValue({ id: 42 });
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInDetachedMode).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
    openInDetachedMode.mockRestore();
  });

  it("reports detached Keycloak enrollment handoff failures without starting OIDC", async () => {
    const error = new Error("Window creation failed");
    const openInDetachedMode = jest.spyOn(QuickAccessService, "openInDetachedMode").mockRejectedValue(error);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.startEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", error);
    openInDetachedMode.mockRestore();
  });

  it("rejects cryptographic login outside extension-owned Quick Access UI", async () => {
    const worker = { name: "Auth", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("opens a Keycloak login Quick Access in detached mode without starting cryptographic login", async () => {
    const openInDetachedMode = jest.spyOn(QuickAccessService, "openInDetachedMode").mockResolvedValue({ id: 42 });
    const open = jest.spyOn(QuickAccessService, "open");
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInDetachedMode).toHaveBeenCalledWith([{ name: "feature", value: "keycloak-sso" }]);
    expect(open).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
    openInDetachedMode.mockRestore();
    open.mockRestore();
  });

  it("rejects detached Keycloak login handoff outside Quick Access", async () => {
    const openInDetachedMode = jest.spyOn(QuickAccessService, "openInDetachedMode").mockResolvedValue({ id: 42 });
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInDetachedMode).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
    openInDetachedMode.mockRestore();
  });

  it("reports detached Keycloak login handoff failures without starting cryptographic login", async () => {
    const error = new Error("Window creation failed");
    const openInDetachedMode = jest.spyOn(QuickAccessService, "openInDetachedMode").mockRejectedValue(error);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", error);
    openInDetachedMode.mockRestore();
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
