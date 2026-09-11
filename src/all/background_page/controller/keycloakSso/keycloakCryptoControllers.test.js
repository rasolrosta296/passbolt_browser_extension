import KeycloakCryptoEnrollmentController from "./keycloakCryptoEnrollmentController";
import KeycloakCryptoEnrollmentOpenDetachedController from "./keycloakCryptoEnrollmentOpenDetachedController";
import KeycloakCryptoEnrollmentStartController from "./keycloakCryptoEnrollmentStartController";
import KeycloakCryptoLoginController from "./keycloakCryptoLoginController";
import KeycloakCryptoLoginOpenDetachedController from "./keycloakCryptoLoginOpenDetachedController";
import KeycloakCryptoEnrollmentStatusController from "./keycloakCryptoEnrollmentStatusController";
import KeycloakIdentityUnlinkController from "./keycloakIdentityUnlinkController";
import KeycloakIdentityLinkController from "./keycloakIdentityLinkController";
import KeycloakIdentityLinkOpenDetachedController from "./keycloakIdentityLinkOpenDetachedController";
import KeycloakCryptoSsoService from "../../service/keycloakSso/keycloakCryptoSsoService";
import KeycloakIdentityLinkTabService from "../../service/keycloakSso/keycloakIdentityLinkTabService";
import { QuickAccessService } from "../../service/ui/quickAccess.service";

jest.mock("../../service/keycloakSso/keycloakCryptoSsoService");
jest.mock("../../service/keycloakSso/keycloakIdentityLinkTabService");

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

  it("opens a Keycloak enrollment Quick Access in a durable tab without starting OIDC", async () => {
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockResolvedValue({ id: 42 });
    const open = jest.spyOn(QuickAccessService, "open");
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInTabMode).toHaveBeenCalledWith([{ name: "feature", value: "keycloak-sso" }]);
    expect(open).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoService.prototype.startEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
    openInTabMode.mockRestore();
    open.mockRestore();
  });

  it("rejects detached Keycloak enrollment handoff outside Quick Access", async () => {
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockResolvedValue({ id: 42 });
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInTabMode).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
    openInTabMode.mockRestore();
  });

  it("reports detached Keycloak enrollment handoff failures without starting OIDC", async () => {
    const error = new Error("Window creation failed");
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockRejectedValue(error);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.startEnrollment).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", error);
    openInTabMode.mockRestore();
  });

  it("rejects cryptographic login outside extension-owned Quick Access UI", async () => {
    const worker = { name: "Auth", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("opens a Keycloak login Quick Access in a durable tab without starting cryptographic login", async () => {
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockResolvedValue({ id: 42 });
    const open = jest.spyOn(QuickAccessService, "open");
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInTabMode).toHaveBeenCalledWith([{ name: "feature", value: "keycloak-sso" }]);
    expect(open).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
    openInTabMode.mockRestore();
    open.mockRestore();
  });

  it("rejects detached Keycloak login handoff outside Quick Access", async () => {
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockResolvedValue({ id: 42 });
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInTabMode).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
    openInTabMode.mockRestore();
  });

  it("reports detached Keycloak login handoff failures without starting cryptographic login", async () => {
    const error = new Error("Window creation failed");
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockRejectedValue(error);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", error);
    openInTabMode.mockRestore();
  });

  it("allows cryptographic login from extension-owned Quick Access UI", async () => {
    KeycloakCryptoSsoService.prototype.login.mockResolvedValue(undefined);
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoLoginController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.login).toHaveBeenCalledTimes(1);
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
  });

  it("returns identity-link and local-enrollment status only to extension-owned Quick Access UI", async () => {
    KeycloakCryptoSsoService.prototype.getManagementStatus.mockResolvedValue({ linked: true, enrolled: true });
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentStatusController(worker, "request-id", {}, {});

    await controller._exec();

    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS", { linked: true, enrolled: true });
  });

  it("rejects local enrollment status outside extension-owned Quick Access UI", async () => {
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakCryptoEnrollmentStatusController(worker, "request-id", {}, {});

    await controller._exec();

    expect(KeycloakCryptoSsoService.prototype.getManagementStatus).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("links only from extension-owned Quick Access using the configured Passbolt account domain", async () => {
    KeycloakIdentityLinkTabService.link.mockResolvedValue();
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const account = { domain: "https://passbolt.example.test" };
    const controller = new KeycloakIdentityLinkController(worker, "request-id", account);

    await controller._exec();

    expect(KeycloakIdentityLinkTabService.link).toHaveBeenCalledWith(account.domain);
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
  });

  it("rejects identity linking outside extension-owned Quick Access", async () => {
    const worker = { name: "App", port: { emit: jest.fn() } };
    const controller = new KeycloakIdentityLinkController(worker, "request-id", { domain: "https://example.test" });

    await controller._exec();

    expect(KeycloakIdentityLinkTabService.link).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "ERROR", expect.any(Error));
  });

  it("opens identity-link management in a durable tab without starting the browser link flow", async () => {
    const openInTabMode = jest.spyOn(QuickAccessService, "openInTabMode").mockResolvedValue({ id: 42 });
    const worker = { name: "QuickAccess", port: { emit: jest.fn() } };
    const controller = new KeycloakIdentityLinkOpenDetachedController(worker, "request-id");

    await controller._exec();

    expect(openInTabMode).toHaveBeenCalledWith([{ name: "feature", value: "keycloak-sso" }]);
    expect(KeycloakIdentityLinkTabService.link).not.toHaveBeenCalled();
    expect(worker.port.emit).toHaveBeenCalledWith("request-id", "SUCCESS");
    openInTabMode.mockRestore();
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
