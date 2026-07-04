
'use strict';

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.storage.local.set({
      detectionLog: [],
      settings: {
        enabled: true
      }
    });
    console.log('PasteGuard installed. Storage initialised.');
  }
});
