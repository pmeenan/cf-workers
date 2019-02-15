let ENABLED = false;
const DISABLED_ICON = {
  "16": "disabled/16.png",
  "24": "disabled/24.png",
  "32": "disabled/32.png",
  "48": "disabled/48.png",
  "64": "disabled/64.png",
  "128": "disabled/128.png"
};
const ENABLED_ICON = {
  "16": "enabled/16.png",
  "24": "enabled/24.png",
  "32": "enabled/32.png",
  "48": "enabled/48.png",
  "64": "enabled/64.png",
  "128": "enabled/128.png"
};


function enable(tab) {
  console.log('Enabling for tab id: ' + tab.id);
  chrome.browserAction.setIcon({path: ENABLED_ICON, tabId: tab.id});
  ENABLED = true;
}

function disable() {
  chrome.browserAction.setIcon({path: DISABLED_ICON});
  ENABLED = false;
}

chrome.browserAction.onClicked.addListener(function(tab) {
  if (ENABLED) {
    disable();
  } else {
    enable(tab);
  }
})