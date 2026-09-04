const MAX_OIDC_MILLISECONDS = 5 * 60 * 1000;

export default class KeycloakOidcTabService {
  static async authenticate(authorizationUrl, passboltOrigin) {
    const authorization = new URL(authorizationUrl);
    const expectedOrigin = new URL(passboltOrigin).origin;
    if (authorization.protocol !== "https:") {
      throw new TypeError("The OIDC authorization URL must use HTTPS.");
    }
    const tab = await browser.tabs.create({ url: authorization.href, active: true });
    if (!Number.isInteger(tab.id)) {
      throw new Error("The OIDC browser tab could not be created.");
    }
    try {
      await new Promise((resolve, reject) => {
        let timeout;
        const cleanup = () => {
          clearTimeout(timeout);
          browser.tabs.onUpdated.removeListener(onUpdated);
          browser.tabs.onRemoved.removeListener(onRemoved);
        };
        const onUpdated = (tabId, changeInfo) => {
          if (tabId !== tab.id || typeof changeInfo.url !== "string") {
            return;
          }
          const current = new URL(changeInfo.url);
          if (current.origin !== expectedOrigin) {
            return;
          }
          if (current.pathname === "/auth/keycloak/crypto/complete") {
            cleanup();
            resolve();
          } else if (current.pathname === "/auth/keycloak/error.json") {
            cleanup();
            reject(new Error("Keycloak authentication failed."));
          }
        };
        const onRemoved = (tabId) => {
          if (tabId === tab.id) {
            cleanup();
            reject(new Error("Keycloak authentication was cancelled."));
          }
        };
        browser.tabs.onUpdated.addListener(onUpdated);
        browser.tabs.onRemoved.addListener(onRemoved);
        timeout = setTimeout(() => {
          cleanup();
          reject(new Error("Keycloak authentication expired."));
        }, MAX_OIDC_MILLISECONDS);
      });
    } finally {
      await browser.tabs.remove(tab.id).catch(() => undefined);
    }
  }
}
