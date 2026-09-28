import Validator from "validator";
import GroupEntity from "passbolt-styleguide/src/shared/models/entity/group/groupEntity";
import GroupModel from "../../model/group/groupModel";
import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import FindAndUpdateGroupsLocalStorageService from "../group/findAndUpdateGroupsLocalStorageService";
import GetPassphraseService from "../passphrase/getPassphraseService";
import GroupUpdateService from "../group/groupUpdateService";
import ProgressService from "../progress/progressService";
import i18n from "../../sdk/i18n";

export default class KeycloakGroupProvisioningService {
  constructor(apiClientOptions, account) {
    this.api = new KeycloakCryptoSsoApiService(apiClientOptions);
    this.account = account;
    this.apiClientOptions = apiClientOptions;
    this.groupModel = new GroupModel(apiClientOptions, account);
    this.findAndUpdateGroups = new FindAndUpdateGroupsLocalStorageService(account, apiClientOptions);
    this.getPassphraseService = new GetPassphraseService(account);
  }

  async findPending() {
    const response = await this.api.getPendingGroupMemberships();
    if (!response || !Array.isArray(response.items)) {
      throw new Error("The Keycloak group-provisioning queue response is invalid.");
    }
    for (const item of response.items) {
      if (!item || !Validator.isUUID(item.id) || !Validator.isUUID(item.group_id) || !Validator.isUUID(item.user_id)) {
        throw new Error("The Keycloak group-provisioning queue item is invalid.");
      }
    }
    return response.items;
  }

  async completePending(worker) {
    const pending = await this.findPending();
    if (pending.length === 0) {
      return { completed: 0 };
    }
    await this.findAndUpdateGroups.findAndUpdateAll();
    let passphrase = null;
    let completed = 0;
    try {
      for (const item of pending) {
        const originalGroup = await this.groupModel.getById(item.group_id);
        if (!(originalGroup instanceof GroupEntity) || !originalGroup.groupsUsers) {
          throw new Error("The mapped Passbolt group is unavailable.");
        }
        if (!originalGroup.groupsUsers.items.some((groupUser) => groupUser.userId === item.user_id)) {
          passphrase ??= await this.getPassphraseService.getPassphrase(worker);
          const groupDto = originalGroup.toDto({ groups_users: true });
          groupDto.groups_users.push({
            user_id: item.user_id,
            is_admin: false,
          });
          const progress = new ProgressService(worker, i18n.t("Applying Keycloak group access ..."));
          try {
            await new GroupUpdateService(this.apiClientOptions, this.account, progress).exec(
              new GroupEntity(groupDto),
              passphrase,
            );
          } finally {
            progress.close();
          }
        }
        await this.api.completePendingGroupMembership(item.id);
        completed++;
      }

      return { completed };
    } finally {
      passphrase = null;
    }
  }
}
