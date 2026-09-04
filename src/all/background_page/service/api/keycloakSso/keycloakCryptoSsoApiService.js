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

  async revokeEnrollments() {
    return (await this.client("/auth/keycloak/crypto/enrollments/revoke").create({})).body;
  }

  client(resourceName) {
    this.apiClientOptions.setResourceName(resourceName);
    return new ApiClient(this.apiClientOptions);
  }
}
