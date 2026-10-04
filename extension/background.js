// Clicking the toolbar icon opens the side panel and grants activeTab for
// the current tab, so Fine Print only ever reads pages the user asks it to.
chrome.action.onClicked.addListener((tab) => {
  chrome.sidePanel.open({ windowId: tab.windowId });
  chrome.runtime.sendMessage({ type: 'fine-print:scan', tabId: tab.id }).catch(() => {
    // Side panel not loaded yet; it scans the active tab on load.
  });
});
