const DATABASE_NAME = "passbolt-keycloak-ce-crypto-sso-v1";
const DATABASE_VERSION = 1;
const STORE_NAME = "browser_profile_enrollments";

export default class BrowserProfileEnrollmentStorage {
  static async save(enrollment) {
    if (
      !enrollment?.storageKey ||
      !(enrollment.kd instanceof CryptoKey) ||
      !(enrollment.signingPrivateKey instanceof CryptoKey)
    ) {
      throw new TypeError("Invalid browser-profile enrollment.");
    }
    const database = await this.open();
    try {
      await new Promise((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, "readwrite");
        transaction.objectStore(STORE_NAME).put(enrollment, enrollment.storageKey);
        transaction.oncomplete = resolve;
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error);
      });
    } finally {
      database.close();
    }
  }

  static async get(storageKey) {
    const database = await this.open();
    try {
      return await new Promise((resolve, reject) => {
        const request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(storageKey);
        request.onsuccess = () => resolve(request.result ?? null);
        request.onerror = () => reject(request.error);
      });
    } finally {
      database.close();
    }
  }

  static async remove(storageKey) {
    const database = await this.open();
    try {
      await new Promise((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, "readwrite");
        transaction.objectStore(STORE_NAME).delete(storageKey);
        transaction.oncomplete = resolve;
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error);
      });
    } finally {
      database.close();
    }
  }

  static storageKey(origin, userId) {
    return `${new URL(origin).origin}|${userId}`;
  }

  static open() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
      request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
}
