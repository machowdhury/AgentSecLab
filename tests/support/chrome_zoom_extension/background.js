/* Qualification helper: apply the same Chrome zoom a learner would choose. */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.type !== "setZoom") return false;
  chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || tab.id == null) {
      sendResponse({ ok: false, error: "no_tab" });
      return;
    }
    chrome.tabs.setZoom(tab.id, message.factor, () => {
      if (chrome.runtime.lastError) {
        sendResponse({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      chrome.tabs.getZoom(tab.id, (actual) => sendResponse({ ok: true, factor: actual }));
    });
  });
  return true;
});
