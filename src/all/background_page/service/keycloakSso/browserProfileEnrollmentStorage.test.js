import BrowserProfileEnrollmentStorage from "./browserProfileEnrollmentStorage";

function installIndexedDbDouble() {
  const records = new Map();
  let initialized = false;
  global.indexedDB = {
    open: jest.fn(() => {
      const request = {};
      const database = {
        close: jest.fn(),
        createObjectStore: jest.fn(),
        transaction: jest.fn(() => {
          const transaction = {
            error: null,
            objectStore: () => ({
              put: (value, key) => {
                records.set(key, structuredClone(value));
                setTimeout(() => transaction.oncomplete?.(), 0);
              },
              get: (key) => {
                const getRequest = {};
                setTimeout(() => {
                  getRequest.result = records.has(key) ? structuredClone(records.get(key)) : undefined;
                  getRequest.onsuccess?.();
                }, 0);
                return getRequest;
              },
              delete: (key) => {
                records.delete(key);
                setTimeout(() => transaction.oncomplete?.(), 0);
              },
            }),
          };
          return transaction;
        }),
      };
      request.result = database;
      setTimeout(() => {
        if (!initialized) {
          initialized = true;
          request.onupgradeneeded?.();
        }
        request.onsuccess?.();
      }, 0);
      return request;
    }),
  };
}

describe("BrowserProfileEnrollmentStorage", () => {
  beforeEach(() => installIndexedDbDouble());

  it("structured-clones non-extractable keys and deletion destroys storage access", async () => {
    const kd = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const signing = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const storageKey = BrowserProfileEnrollmentStorage.storageKey(
      "https://passbolt.example.test",
      "10000000-0000-4000-8000-000000000001",
    );
    await BrowserProfileEnrollmentStorage.save({ storageKey, kd, signingPrivateKey: signing.privateKey });
    const restored = await BrowserProfileEnrollmentStorage.get(storageKey);
    expect(restored.kd.extractable).toBe(false);
    expect(restored.signingPrivateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", restored.kd)).rejects.toThrow();
    await expect(crypto.subtle.exportKey("pkcs8", restored.signingPrivateKey)).rejects.toThrow();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode("dummy bytes");
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, restored.kd, plaintext);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, restored.kd, ciphertext);
    expect(new Uint8Array(decrypted)).toEqual(plaintext);
    expect(JSON.stringify(restored.kd)).toBe("{}");
    await BrowserProfileEnrollmentStorage.remove(storageKey);
    await expect(BrowserProfileEnrollmentStorage.get(storageKey)).resolves.toBeNull();
  });
});
