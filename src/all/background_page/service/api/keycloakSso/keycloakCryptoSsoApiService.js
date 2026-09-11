import { ApiClient } from "passbolt-styleguide/src/shared/lib/apiClient/apiClient";

export default class KeycloakCryptoSsoApiService {
  constructor(apiClientOptions) {
    this.apiClientOptions = apiClientOptions;
  }

  async startEnrollment() {
    return (await this.client("/auth/keycloak/crypto/enroll/start").create({})).body;
  }

  async enroll(payload) {
    return (await this.client("/auth/keycloak/crypto/enroll").create(payload)).body;
  }

  async startLogin(payload) {
    return (await this.client("/auth/keycloak/crypto/login/start").create(payload)).body;
  }

  async release(payload) {
    return (await this.client("/auth/keycloak/crypto/release").create(payload)).body;
  }

  async startPassphraseRotation() {
    return (await this.client("/auth/keycloak/crypto/rotation/start").create({})).body;
  }

  async completePassphraseRotation(rotationCapability) {
    return (
      await this.client("/auth/keycloak/crypto/rotation/complete").create({
        rotation_capability: rotationCapability,
      })
    ).body;
  }

  async failPassphraseRotation(rotationCapability) {
    return (
      await this.client("/auth/keycloak/crypto/rotation/fail").create({
        rotation_capability: rotationCapability,
      })
    ).body;
  }

  async unlinkIdentity() {
    return (
      await this.client("/auth/keycloak/unlink").create({
        confirmation: "unlink_keycloak_identity",
      })
    ).body;
  }

  async getIdentityLinkStatus() {
    return (await this.client("/auth/keycloak/link/status").findAll()).body;
  }

  client(resourceName) {
    this.apiClientOptions.setResourceName(resourceName);
    return new ApiClient(this.apiClientOptions);
  }
}
