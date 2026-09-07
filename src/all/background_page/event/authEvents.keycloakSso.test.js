import KeycloakCryptoEnrollmentOpenDetachedController from "../controller/keycloakSso/keycloakCryptoEnrollmentOpenDetachedController";
import KeycloakCryptoLoginOpenDetachedController from "../controller/keycloakSso/keycloakCryptoLoginOpenDetachedController";
import { AuthEvents } from "./authEvents";

jest.mock("../controller/keycloakSso/keycloakCryptoEnrollmentOpenDetachedController");
jest.mock("../controller/keycloakSso/keycloakCryptoLoginOpenDetachedController");

describe("AuthEvents Keycloak enrollment handoff", () => {
  it("registers and executes the detached enrollment handoff event", async () => {
    const listeners = new Map();
    const worker = {
      name: "QuickAccess",
      port: {
        on: jest.fn((name, listener) => listeners.set(name, listener)),
      },
    };
    KeycloakCryptoEnrollmentOpenDetachedController.prototype._exec.mockResolvedValue();

    AuthEvents.listen(worker, { api: "options" }, { id: "account" });
    const listener = listeners.get("passbolt.keycloak-sso.crypto-enroll.open-detached");
    expect(listener).toEqual(expect.any(Function));

    await listener("request-id");

    expect(KeycloakCryptoEnrollmentOpenDetachedController).toHaveBeenCalledWith(worker, "request-id");
    expect(KeycloakCryptoEnrollmentOpenDetachedController.prototype._exec).toHaveBeenCalledTimes(1);
  });

  it("registers and executes the detached login handoff event", async () => {
    const listeners = new Map();
    const worker = {
      name: "QuickAccess",
      port: {
        on: jest.fn((name, listener) => listeners.set(name, listener)),
      },
    };
    KeycloakCryptoLoginOpenDetachedController.prototype._exec.mockResolvedValue();

    AuthEvents.listen(worker, { api: "options" }, { id: "account" });
    const listener = listeners.get("passbolt.keycloak-sso.crypto-login.open-detached");
    expect(listener).toEqual(expect.any(Function));

    await listener("request-id");

    expect(KeycloakCryptoLoginOpenDetachedController).toHaveBeenCalledWith(worker, "request-id");
    expect(KeycloakCryptoLoginOpenDetachedController.prototype._exec).toHaveBeenCalledTimes(1);
  });
});
