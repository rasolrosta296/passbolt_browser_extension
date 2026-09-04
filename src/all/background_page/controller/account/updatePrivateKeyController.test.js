/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) 2022 Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) 2022 Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         3.6.3
 */
import "../../../../../test/mocks/mockSsoDataStorage";
import "../../../../../test/mocks/mockCryptoKey";
import { v4 as uuidv4 } from "uuid";
import { pgpKeys } from "passbolt-styleguide/test/fixture/pgpKeys/keys";
import MockExtension from "../../../../../test/mocks/mockExtension";
import { defaultApiClientOptions } from "passbolt-styleguide/src/shared/lib/apiClient/apiClientOptions.test.data";
import DecryptPrivateKeyService from "../../service/crypto/decryptPrivateKeyService";
import UpdatePrivateKeyController from "./updatePrivateKeyController";
import { OpenpgpAssertion } from "../../utils/openpgp/openpgpAssertions";
import FileService from "../../service/file/fileService";
import SsoDataStorage from "../../service/indexedDB_storage/ssoDataStorage";
import { clientSsoKit } from "../../model/entity/sso/ssoKitClientPart.test.data";
import GenerateSsoKitService from "../../service/sso/generateSsoKitService";
import { anonymousSiteSettings } from "passbolt-styleguide/src/shared/models/entity/siteSettings/siteSettingsEntity.test.data";
import SiteSettingsEntity from "passbolt-styleguide/src/shared/models/entity/siteSettings/siteSettingsEntity";
import GetOrFindSiteSettingsService from "../../service/siteSettings/getOrFindSiteSettingsService";
import AccountEntity from "../../model/entity/account/accountEntity";
import { defaultAccountDto } from "../../model/entity/account/accountEntity.test.data";
import { mockApiResponse, mockApiResponseError } from "../../../../../test/mocks/mockApiResponse";
import { enableFetchMocks } from "jest-fetch-mock";
import SsoKitClientPartEntity from "../../model/entity/sso/ssoKitClientPartEntity";
import SsoKitServerPartEntity from "../../model/entity/sso/ssoKitServerPartEntity";
import PassphraseStorageService from "../../service/session_storage/passphraseStorageService";
import InvalidMasterPasswordError from "../../error/invalidMasterPasswordError";
import { generateSsoKitServerData } from "../../model/entity/sso/ssoKitServerPart.test.data";
import KeycloakCryptoSsoRotationService from "../../service/keycloakSso/keycloakCryptoSsoRotationService";

const mockedSaveFile = jest.spyOn(FileService, "saveFile");

beforeEach(() => {
  enableFetchMocks();
  jest.clearAllMocks();
  fetch.resetMocks();
});

describe("UpdatePrivateKeyController", () => {
  const account = new AccountEntity(defaultAccountDto());
  const mockOrganisationSettingCall = (ssoEnabled = false, keycloakSsoEnabled = false) => {
    const organizationSettings = anonymousSiteSettings();
    if (ssoEnabled) {
      organizationSettings.passbolt.plugins.sso = { enabled: true };
    }
    if (keycloakSsoEnabled) {
      organizationSettings.passbolt.plugins.keycloakSso = { enabled: true };
    }
    jest
      .spyOn(GetOrFindSiteSettingsService.prototype, "getOrFind")
      .mockImplementation(() => new SiteSettingsEntity(organizationSettings));
  };

  describe("UpdatePrivateKeyController::exec", () => {
    it("Should trigger the download of the recovery kit with the new passphrase.", async () => {
      expect.assertions(4);

      await MockExtension.withConfiguredAccount();
      mockOrganisationSettingCall();
      mockedSaveFile.mockImplementation(async (fileName, fileContent, fileContentType, workerTabId) => {
        expect(fileName).toStrictEqual("passbolt-recovery-kit.asc");
        expect(fileContentType).toStrictEqual("text/plain");
        expect(workerTabId).toStrictEqual(worker.tab.id);

        const key = await OpenpgpAssertion.readKeyOrFail(fileContent);
        OpenpgpAssertion.assertEncryptedPrivateKey(key);

        const decryptedPrivateKey = await DecryptPrivateKeyService.decrypt(key, newPassphrase);
        expect(decryptedPrivateKey).toBeTruthy();
      });

      const worker = {
        tab: {
          id: uuidv4(),
        },
      };

      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      const oldPassphrase = pgpKeys.ada.passphrase;
      const newPassphrase = "newPassphrase";
      await controller.exec(oldPassphrase, newPassphrase);
    });

    it("Should throw an error if no passphrase is provided.", async () => {
      expect.assertions(2);
      await MockExtension.withConfiguredAccount();
      const controller = new UpdatePrivateKeyController(null, null, defaultApiClientOptions(), account);

      const nullPassphrase = null;
      const stringPassphrase = "stringPassphrase";
      const expectedError = new Error("The old and new passphrase have to be string");
      try {
        await controller.exec(nullPassphrase, stringPassphrase);
      } catch (e) {
        expect(e).toStrictEqual(expectedError);
      }

      try {
        await controller.exec(stringPassphrase, nullPassphrase);
      } catch (e) {
        expect(e).toStrictEqual(expectedError);
      }
    });

    it("Should throw an error if passphrases are not strings.", async () => {
      expect.assertions(2);
      await MockExtension.withConfiguredAccount();
      const controller = new UpdatePrivateKeyController(null, null, defaultApiClientOptions(), account);

      const notStringPassphrase = {};
      const stringPassphrase = "stringPassphrase";
      const expectedError = new Error("The old and new passphrase have to be string");
      try {
        await controller.exec(notStringPassphrase, stringPassphrase);
      } catch (e) {
        expect(e).toStrictEqual(expectedError);
      }

      try {
        await controller.exec(stringPassphrase, notStringPassphrase);
      } catch (e) {
        expect(e).toStrictEqual(expectedError);
      }
    });

    it("Should update the local SSO kit if one already exists.", async () => {
      expect.assertions(2);
      const data = await generateSsoKitServerData();
      const dto = { data };

      const newPassphrase = "newPassphrase";
      const ssoKit = await clientSsoKit();
      const newSsoKitId = uuidv4();
      const newSsoKit = new SsoKitClientPartEntity(await clientSsoKit({ id: newSsoKitId }));
      const worker = {
        tab: {
          id: uuidv4(),
        },
      };

      await MockExtension.withConfiguredAccount();
      SsoDataStorage.setMockedData(ssoKit);

      expect.assertions(3);

      mockOrganisationSettingCall(true);
      fetch.doMockOnceIf(new RegExp(`/sso/keys/${ssoKit.id}.json`), () => mockApiResponse({}));
      fetch.doMockOnceIf(new RegExp("/sso/keys.json"), () => mockApiResponse({ id: newSsoKitId, data: data }));

      jest.spyOn(GenerateSsoKitService, "generateSsoKits").mockImplementation((passphrase, providerId) => {
        expect(passphrase).toBe(newPassphrase);
        expect(providerId).toBe(ssoKit.provider);

        return {
          serverPart: new SsoKitServerPartEntity(dto),
          clientPart: newSsoKit,
        };
      });

      SsoDataStorage.save.mockImplementation((kit) => {
        expect(kit).toBe(newSsoKit);
      });

      mockedSaveFile.mockImplementation(async () => {});

      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      const oldPassphrase = pgpKeys.ada.passphrase;
      await controller.exec(oldPassphrase, newPassphrase);
    });

    it("Should not create a local SSO kit if none exists.", async () => {
      expect.assertions(2);
      const worker = {
        tab: {
          id: uuidv4(),
        },
      };

      await MockExtension.withConfiguredAccount();
      SsoDataStorage.setMockedData(null);

      expect.assertions(2);
      mockOrganisationSettingCall(true);

      const shouldNotHaveBeenCalledError = new Error("This API request should not have been made");
      fetch.doMockOnceIf(/\/sso\/keys\/[a-fA-F0-9-]+\.json/, () => {
        throw shouldNotHaveBeenCalledError;
      });
      fetch.doMockOnceIf(/\/sso\/keys\.json/, () => {
        throw shouldNotHaveBeenCalledError;
      });

      jest.spyOn(GenerateSsoKitService, "generateSsoKits");

      mockedSaveFile.mockImplementation(() => {});

      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      await controller.exec(pgpKeys.ada.passphrase, "newPassphrase");

      expect(GenerateSsoKitService.generateSsoKits).not.toHaveBeenCalled();
      expect(SsoDataStorage.save).not.toHaveBeenCalled();
    });

    it("Should not update the passsphrase if the kit can't be send to the server.", async () => {
      mockOrganisationSettingCall(true);
      const data = await generateSsoKitServerData();
      const dto = { data };
      const newPassphrase = "newPassphrase";
      const ssoKit = await clientSsoKit();
      const newSsoKitId = uuidv4();
      const newSsoKit = new SsoKitClientPartEntity(await clientSsoKit({ id: newSsoKitId }));
      const worker = {
        tab: {
          id: uuidv4(),
        },
      };

      await MockExtension.withConfiguredAccount();
      SsoDataStorage.setMockedData(ssoKit);

      expect.assertions(3);
      fetch.doMockOnceIf(new RegExp(`/sso/keys/${ssoKit.id}.json`), () => mockApiResponse({}));

      const expectedError = new Error("Something went wrong");
      fetch.doMockOnceIf(new RegExp("/sso/keys.json"), () => {
        throw expectedError;
      });

      jest.spyOn(GenerateSsoKitService, "generateSsoKits").mockImplementation(() => ({
        serverPart: new SsoKitServerPartEntity(dto),
        clientPart: newSsoKit,
      }));
      jest.spyOn(PassphraseStorageService, "flushPassphrase");

      mockedSaveFile.mockImplementation(async () => {});

      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      const oldPassphrase = pgpKeys.ada.passphrase;
      try {
        await controller.exec(oldPassphrase, newPassphrase);
      } catch {
        // Expected to throw, error is intentionally ignored
      }

      expect(SsoDataStorage.save).not.toHaveBeenCalled();
      expect(PassphraseStorageService.flushPassphrase).not.toHaveBeenCalled();
      expect(mockedSaveFile).not.toHaveBeenCalled();
    });

    it("Should ignore the sso kit deletion on server side if it gets a 404.", async () => {
      const data = await generateSsoKitServerData();
      const dto = { data };
      const newPassphrase = "newPassphrase";
      const ssoKit = await clientSsoKit();
      const newSsoKitId = uuidv4();
      const newSsoKit = new SsoKitClientPartEntity(await clientSsoKit({ id: newSsoKitId }));
      const worker = {
        tab: {
          id: uuidv4(),
        },
      };

      await MockExtension.withConfiguredAccount();
      SsoDataStorage.setMockedData(ssoKit);

      expect.assertions(1);

      mockOrganisationSettingCall(true);
      fetch.doMockOnceIf(new RegExp(`/sso/keys/${ssoKit.id}.json`), () => mockApiResponseError(404));
      fetch.doMockOnceIf(new RegExp("/sso/keys.json"), () => mockApiResponse({ id: newSsoKitId, data: data }));

      jest.spyOn(GenerateSsoKitService, "generateSsoKits").mockImplementation(() => ({
        serverPart: new SsoKitServerPartEntity(dto),
        clientPart: newSsoKit,
      }));

      SsoDataStorage.save.mockImplementation((kit) => {
        expect(kit).toBe(newSsoKit);
      });

      mockedSaveFile.mockImplementation(async () => {});

      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      const oldPassphrase = pgpKeys.ada.passphrase;
      await controller.exec(oldPassphrase, newPassphrase);
    });

    it("Should not generate another SSO kit if the passphrase can't be rotated.", async () => {
      const newPassphrase = "newPassphrase";
      const ssoKit = await clientSsoKit();
      const newSsoKitId = uuidv4();
      const newSsoKit = new SsoKitClientPartEntity(await clientSsoKit({ id: newSsoKitId }));
      const worker = {
        tab: {
          id: uuidv4(),
        },
      };

      await MockExtension.withConfiguredAccount();
      SsoDataStorage.setMockedData(ssoKit);

      expect.assertions(4);

      mockOrganisationSettingCall(true);

      const shouldNotHaveBeenCalledError = new Error("This API request should not have been made");
      fetch.doMockOnceIf(/\/sso\/keys\/[a-fA-F0-9-]+\.json/, () => {
        throw shouldNotHaveBeenCalledError;
      });
      fetch.doMockOnceIf(/\/sso\/keys\.json/, () => {
        throw shouldNotHaveBeenCalledError;
      });

      jest.spyOn(GenerateSsoKitService, "generateSsoKits");

      SsoDataStorage.save.mockImplementation((kit) => {
        expect(kit).toBe(newSsoKit);
      });

      mockedSaveFile.mockImplementation(async () => {});

      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      try {
        await controller.exec("wrong passphrase", newPassphrase);
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidMasterPasswordError);
      }

      expect(GenerateSsoKitService.generateSsoKits).not.toHaveBeenCalled();
      expect(SsoDataStorage.save).not.toHaveBeenCalled();
      expect(mockedSaveFile).not.toHaveBeenCalled();
    });

    it("Should hold the Keycloak rotation barrier across the private-key update.", async () => {
      const worker = { tab: { id: uuidv4() } };
      const clientEnrollmentUuid = uuidv4();
      const order = [];
      mockOrganisationSettingCall(false, true);
      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      jest.spyOn(controller.accountModel, "rotatePrivateKeyPassphrase").mockImplementation(async () => {
        order.push("validate");
        return "rotated-armored-key";
      });
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "begin").mockImplementation(async () => {
        order.push("start-barrier");
        return { capability: "A".repeat(43), clientEnrollmentUuids: [clientEnrollmentUuid] };
      });
      jest.spyOn(controller.accountModel, "updatePrivateKey").mockImplementation(async () => {
        order.push("persist-rotation");
      });
      jest.spyOn(PassphraseStorageService, "flushPassphrase").mockResolvedValue();
      mockedSaveFile.mockImplementation(async () => order.push("save-recovery-kit"));
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "removeLocalEnrollments").mockImplementation(async () => {
        order.push("cleanup-local");
      });
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "complete").mockImplementation(async () => {
        order.push("complete-barrier");
      });

      await controller.exec("old-passphrase", "new-passphrase");

      expect(order).toEqual([
        "validate",
        "start-barrier",
        "cleanup-local",
        "persist-rotation",
        "complete-barrier",
        "save-recovery-kit",
      ]);
      expect(controller.keycloakCryptoSsoRotationService.removeLocalEnrollments).toHaveBeenCalledWith([
        clientEnrollmentUuid,
      ]);
    });

    it("Should abort passphrase rotation when the Keycloak rotation barrier cannot start.", async () => {
      const worker = { tab: { id: uuidv4() } };
      mockOrganisationSettingCall(false, true);
      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      jest.spyOn(controller.accountModel, "rotatePrivateKeyPassphrase").mockResolvedValue("rotated-armored-key");
      jest
        .spyOn(controller.keycloakCryptoSsoRotationService, "begin")
        .mockRejectedValue(new Error("Rotation barrier failed"));
      jest.spyOn(controller.accountModel, "updatePrivateKey");
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "removeLocalEnrollments");

      await expect(controller.exec("old-passphrase", "new-passphrase")).rejects.toThrow("Rotation barrier failed");

      expect(controller.accountModel.updatePrivateKey).not.toHaveBeenCalled();
      expect(mockedSaveFile).not.toHaveBeenCalled();
      expect(controller.keycloakCryptoSsoRotationService.removeLocalEnrollments).not.toHaveBeenCalled();
    });

    it("Should fail the active barrier when local enrollment cleanup fails before the key update.", async () => {
      const worker = { tab: { id: uuidv4() } };
      const clientEnrollmentUuid = uuidv4();
      mockOrganisationSettingCall(false, true);
      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      jest.spyOn(controller.accountModel, "rotatePrivateKeyPassphrase").mockResolvedValue("rotated-armored-key");
      jest
        .spyOn(controller.keycloakCryptoSsoRotationService, "begin")
        .mockResolvedValue({ capability: "A".repeat(43), clientEnrollmentUuids: [clientEnrollmentUuid] });
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "fail").mockResolvedValue();
      jest.spyOn(controller.accountModel, "updatePrivateKey").mockResolvedValue();
      jest.spyOn(PassphraseStorageService, "flushPassphrase").mockResolvedValue();
      mockedSaveFile.mockResolvedValue();
      jest
        .spyOn(controller.keycloakCryptoSsoRotationService, "removeLocalEnrollments")
        .mockRejectedValue(new Error("IndexedDB cleanup failed"));

      await expect(controller.exec("old-passphrase", "new-passphrase")).rejects.toThrow("IndexedDB cleanup failed");

      expect(controller.keycloakCryptoSsoRotationService.begin).toHaveBeenCalledTimes(1);
      expect(controller.keycloakCryptoSsoRotationService.fail).toHaveBeenCalledWith("A".repeat(43));
      expect(controller.accountModel.updatePrivateKey).not.toHaveBeenCalled();
      expect(mockedSaveFile).not.toHaveBeenCalled();
    });

    it("Should leave the barrier active when completion is uncertain after the key update.", async () => {
      const worker = { tab: { id: uuidv4() } };
      mockOrganisationSettingCall(false, true);
      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      jest.spyOn(controller.accountModel, "rotatePrivateKeyPassphrase").mockResolvedValue("rotated-armored-key");
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "begin").mockResolvedValue({
        capability: "A".repeat(43),
        clientEnrollmentUuids: [],
      });
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "removeLocalEnrollments").mockResolvedValue();
      jest.spyOn(controller.accountModel, "updatePrivateKey").mockResolvedValue();
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "complete").mockRejectedValue(new Error("timeout"));
      jest.spyOn(controller.keycloakCryptoSsoRotationService, "fail").mockResolvedValue();

      await expect(controller.exec("old-passphrase", "new-passphrase")).rejects.toThrow("timeout");

      expect(controller.accountModel.updatePrivateKey).toHaveBeenCalledWith("rotated-armored-key");
      expect(controller.keycloakCryptoSsoRotationService.fail).not.toHaveBeenCalled();
    });

    it("Should leave normal passphrase rotation unchanged when Keycloak SSO is disabled.", async () => {
      const worker = { tab: { id: uuidv4() } };
      mockOrganisationSettingCall();
      const controller = new UpdatePrivateKeyController(worker, null, defaultApiClientOptions(), account);
      jest.spyOn(controller.accountModel, "rotatePrivateKeyPassphrase").mockResolvedValue("rotated-armored-key");
      jest.spyOn(controller.accountModel, "updatePrivateKey").mockResolvedValue();
      jest.spyOn(PassphraseStorageService, "flushPassphrase").mockResolvedValue();
      mockedSaveFile.mockResolvedValue();
      jest.spyOn(KeycloakCryptoSsoRotationService.prototype, "begin");

      await controller.exec("old-passphrase", "new-passphrase");

      expect(KeycloakCryptoSsoRotationService.prototype.begin).not.toHaveBeenCalled();
      expect(controller.accountModel.updatePrivateKey).toHaveBeenCalledWith("rotated-armored-key");
    });
  });
});
