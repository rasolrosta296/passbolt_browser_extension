import GroupEntity from "passbolt-styleguide/src/shared/models/entity/group/groupEntity";
import KeycloakCryptoSsoApiService from "../api/keycloakSso/keycloakCryptoSsoApiService";
import GroupModel from "../../model/group/groupModel";
import FindAndUpdateGroupsLocalStorageService from "../group/findAndUpdateGroupsLocalStorageService";
import GetPassphraseService from "../passphrase/getPassphraseService";
import GroupUpdateService from "../group/groupUpdateService";
import ProgressService from "../progress/progressService";
import KeycloakGroupProvisioningService from "./keycloakGroupProvisioningService";

jest.mock("../api/keycloakSso/keycloakCryptoSsoApiService");
jest.mock("../../model/group/groupModel");
jest.mock("../group/findAndUpdateGroupsLocalStorageService");
jest.mock("../passphrase/getPassphraseService");
jest.mock("../group/groupUpdateService");
jest.mock("../progress/progressService");

const membershipId = "8d020e76-4951-58d2-b68e-99e2fc1053f8";
const groupId = "7cd5488d-b1ec-42f6-925d-795620ff2701";
const managerId = "53a9a0c1-8ce8-4cbc-9b38-04938fea2311";
const targetId = "4d2d5c43-a76a-5d4a-8f47-2b1f0268e3d6";

const pending = [{ id: membershipId, group_id: groupId, user_id: targetId }];
const group = (members = [managerId]) =>
  new GroupEntity({
    id: groupId,
    name: "Engineering",
    groups_users: members.map((userId) => ({
      user_id: userId,
      group_id: groupId,
      is_admin: userId === managerId,
    })),
  });

describe("KeycloakGroupProvisioningService", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    KeycloakCryptoSsoApiService.prototype.getPendingGroupMemberships.mockResolvedValue({ items: pending });
    KeycloakCryptoSsoApiService.prototype.completePendingGroupMembership.mockResolvedValue({});
    FindAndUpdateGroupsLocalStorageService.prototype.findAndUpdateAll.mockResolvedValue();
    GroupModel.prototype.getById.mockResolvedValue(group());
    GetPassphraseService.prototype.getPassphrase.mockResolvedValue("dummy-passphrase");
    GroupUpdateService.prototype.exec.mockResolvedValue();
    ProgressService.prototype.close.mockReturnValue();
  });

  it("uses the unchanged group update crypto flow before completing queue state", async () => {
    const worker = { name: "QuickAccess", port: {} };
    const service = new KeycloakGroupProvisioningService({}, {});

    await expect(service.completePending(worker)).resolves.toEqual({ completed: 1 });

    expect(GetPassphraseService.prototype.getPassphrase).toHaveBeenCalledWith(worker);
    expect(GroupUpdateService.prototype.exec).toHaveBeenCalledTimes(1);
    const [updatedGroup, passphrase] = GroupUpdateService.prototype.exec.mock.calls[0];
    expect(passphrase).toBe("dummy-passphrase");
    expect(updatedGroup.groupsUsers.items.some((groupUser) => groupUser.userId === targetId)).toBe(true);
    expect(updatedGroup.groupsUsers.items.find((groupUser) => groupUser.userId === targetId).isAdmin).toBe(false);
    expect(KeycloakCryptoSsoApiService.prototype.completePendingGroupMembership).toHaveBeenCalledWith(membershipId);
    expect(GroupUpdateService.prototype.exec.mock.invocationCallOrder[0]).toBeLessThan(
      KeycloakCryptoSsoApiService.prototype.completePendingGroupMembership.mock.invocationCallOrder[0],
    );
  });

  it("reconciles an already completed core membership without requesting the passphrase", async () => {
    GroupModel.prototype.getById.mockResolvedValue(group([managerId, targetId]));
    const service = new KeycloakGroupProvisioningService({}, {});

    await expect(service.completePending({ name: "QuickAccess" })).resolves.toEqual({ completed: 1 });

    expect(GetPassphraseService.prototype.getPassphrase).not.toHaveBeenCalled();
    expect(GroupUpdateService.prototype.exec).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoApiService.prototype.completePendingGroupMembership).toHaveBeenCalledWith(membershipId);
  });

  it("rejects malformed queue data before asking for a passphrase or updating groups", async () => {
    KeycloakCryptoSsoApiService.prototype.getPendingGroupMemberships.mockResolvedValue({
      items: [{ id: "invalid", group_id: groupId, user_id: targetId }],
    });
    const service = new KeycloakGroupProvisioningService({}, {});

    await expect(service.completePending({ name: "QuickAccess" })).rejects.toThrow(
      "The Keycloak group-provisioning queue item is invalid.",
    );

    expect(GetPassphraseService.prototype.getPassphrase).not.toHaveBeenCalled();
    expect(GroupUpdateService.prototype.exec).not.toHaveBeenCalled();
    expect(KeycloakCryptoSsoApiService.prototype.completePendingGroupMembership).not.toHaveBeenCalled();
  });

  it("does not mark queue state complete when Passbolt group update fails", async () => {
    GroupUpdateService.prototype.exec.mockRejectedValue(new Error("Group update failed"));
    const service = new KeycloakGroupProvisioningService({}, {});

    await expect(service.completePending({ name: "QuickAccess" })).rejects.toThrow("Group update failed");

    expect(KeycloakCryptoSsoApiService.prototype.completePendingGroupMembership).not.toHaveBeenCalled();
    expect(ProgressService.prototype.close).toHaveBeenCalledTimes(1);
  });
});
