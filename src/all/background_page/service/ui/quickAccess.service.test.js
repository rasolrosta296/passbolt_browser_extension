import WorkersSessionStorage from "../sessionStorage/workersSessionStorage";
import { QuickAccessService } from "./quickAccess.service";

jest.mock("../sessionStorage/workersSessionStorage");

describe("QuickAccessService detached mode", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    browser.runtime.getURL.mockReturnValue("chrome-extension://extension-id/quickaccess.html");
    browser.windows.getCurrent = jest.fn().mockResolvedValue({ left: 10, top: 20, width: 1200 });
    browser.windows.create = jest.fn().mockResolvedValue({ id: 42, tabs: [{ id: 84 }] });
    browser.windows.update = jest.fn().mockResolvedValue();
    WorkersSessionStorage.addWorker.mockResolvedValue();
  });

  it("adds detached mode while preserving only the requested Keycloak feature parameter", async () => {
    await QuickAccessService.openInDetachedMode([{ name: "feature", value: "keycloak-sso" }]);

    expect(browser.windows.create).toHaveBeenCalledTimes(1);
    const createData = browser.windows.create.mock.calls[0][0];
    const url = new URL(createData.url);
    expect(url.searchParams.get("feature")).toBe("keycloak-sso");
    expect(url.searchParams.get("uiMode")).toBe("detached");
    expect([...url.searchParams.keys()].sort()).toEqual(["feature", "passbolt", "uiMode"]);
    expect(WorkersSessionStorage.addWorker).toHaveBeenCalledTimes(1);
  });

  it("opens Keycloak Quick Access in a durable extension tab without sensitive bootstrap parameters", async () => {
    browser.tabs.create.mockResolvedValue({ id: 85 });

    await QuickAccessService.openInTabMode([{ name: "feature", value: "keycloak-sso" }]);

    expect(browser.tabs.create).toHaveBeenCalledTimes(1);
    const createData = browser.tabs.create.mock.calls[0][0];
    const url = new URL(createData.url);
    expect(createData.active).toBe(true);
    expect(url.origin).toBe("null");
    expect(url.pathname).toBe("/quickaccess.html");
    expect(url.searchParams.get("feature")).toBe("keycloak-sso");
    expect(url.searchParams.get("uiMode")).toBe("detached");
    expect(url.searchParams.get("surface")).toBe("tab");
    expect([...url.searchParams.keys()].sort()).toEqual(["feature", "passbolt", "surface", "uiMode"]);
    expect(WorkersSessionStorage.addWorker).toHaveBeenCalledTimes(1);
    expect(WorkersSessionStorage.addWorker.mock.calls[0][0].tabId).toBe(85);
  });

  it("fails closed when Chrome does not return a tab identifier", async () => {
    browser.tabs.create.mockResolvedValue({});

    await expect(QuickAccessService.openInTabMode([{ name: "feature", value: "keycloak-sso" }])).rejects.toThrow(
      "The Quick Access tab could not be created.",
    );
    expect(WorkersSessionStorage.addWorker).not.toHaveBeenCalled();
  });
});
