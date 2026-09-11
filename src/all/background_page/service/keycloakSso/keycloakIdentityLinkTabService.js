const MAX_IDENTITY_LINK_MILLISECONDS = 5 * 60 * 1000;

export default class KeycloakIdentityLinkTabService {
  static async link(passboltDomain) {
    const configured = new URL(passboltDomain);
    if (configured.protocol !== "https:" || configured.username !== "" || configured.password !== "") {
      throw new TypeError("The Passbolt URL must use HTTPS.");
    }
    const expectedOrigin = configured.origin;
    const linkUrl = new URL("/auth/keycloak/link", expectedOrigin).href;
    const tab = await browser.tabs.create({ url: linkUrl, active: true });
    if (!Number.isInteger(tab.id)) {
      throw new Error("The Keycloak identity-link tab could not be created.");
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
          let current;
          try {
            current = new URL(changeInfo.url);
          } catch {
            return;
          }
          if (current.origin !== expectedOrigin || current.search !== "" || current.hash !== "") {
            return;
          }
          if (current.pathname === "/auth/keycloak/link/result") {
            cleanup();
            resolve();
          } else if (current.pathname === "/auth/keycloak/link/error") {
            cleanup();
            reject(new Error("Keycloak identity linking failed."));
          }
        };
        const onRemoved = (tabId) => {
          if (tabId === tab.id) {
            cleanup();
            reject(new Error("Keycloak identity linking was cancelled."));
          }
        };
        browser.tabs.onUpdated.addListener(onUpdated);
        browser.tabs.onRemoved.addListener(onRemoved);
        timeout = setTimeout(() => {
          cleanup();
          reject(new Error("Keycloak identity linking expired."));
        }, MAX_IDENTITY_LINK_MILLISECONDS);
      });
    } finally {
      await browser.tabs.remove(tab.id).catch(() => undefined);
    }
  }
}
