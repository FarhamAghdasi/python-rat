class FileManager {
    constructor() {
        this.currentPath = 'C:\\';
        this.selectedFiles = new Set();
        this.currentView = 'grid';
        this.sortBy = 'name';
        this.sortOrder = 'asc';
        this.uploadQueue = [];
        this.selectedClient = SELECTED_CLIENT || '';
        this.isOnline = this.checkClientOnline();
        
        // Check if we have a selected client
        if (this.selectedClient) {
            this.init();
        } else {
            this.showError('Please select a client first');
        }
    }

    checkClientOnline() {
        const select = document.getElementById('client-select');
        if (!select) return false;
        
        const selectedOption = select.options[select.selectedIndex];
        return selectedOption ? selectedOption.dataset.online === '1' : false;
    }

    init() {
        if (!this.selectedClient) {
            this.showError('No client selected. Please select a client from the dropdown.');
            return;
        }
        
        if (!this.isOnline) {
            this.showWarning('Client is offline. Some operations may not work.');
        }
        
        this.setupEventListeners();
        this.loadDirectory(this.currentPath);
        this.setView('grid');
        
        // Setup drag and drop
        this.setupDragAndDrop();
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (this.selectedClient) {
                this.refresh();
            }
        }, 30000);
    }

    setupEventListeners() {
        // Client selection
        const clientSelect = document.getElementById('client-select');
        if (clientSelect) {
            clientSelect.addEventListener('change', (e) => {
                this.selectedClient = e.target.value;
                this.isOnline = this.checkClientOnline();
                
                if (!this.selectedClient) {
                    this.showError('Please select a valid client');
                    return;
                }
                
                // Update session
                window.location.href = `?select_client=${encodeURIComponent(this.selectedClient)}`;
            });
        }

        // Search input
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.search();
            });
        }

        // File upload
        const fileUploadInput = document.getElementById('file-upload-input');
        if (fileUploadInput) {
            fileUploadInput.addEventListener('change', (e) => {
                this.addFilesToQueue(Array.from(e.target.files));
            });
        }

        // Context menu
        document.addEventListener('click', () => {
            this.hideContextMenu();
        });

        document.addEventListener('contextmenu', (e) => {
            if (e.target.closest('.file-item')) {
                e.preventDefault();
                this.showContextMenu(e);
            }
        });
    }

    setupDragAndDrop() {
        const dropZone = document.querySelector('#upload-modal .border-dashed');
        if (!dropZone) return;

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('border-yellow-500', 'bg-gray-800/50');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('border-yellow-500', 'bg-gray-800/50');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-yellow-500', 'bg-gray-800/50');
            
            const files = Array.from(e.dataTransfer.files);
            this.addFilesToQueue(files);
        });
    }

    async loadDirectory(path = '') {
        if (!this.selectedClient) {
            this.showError('Please select a client first');
            return;
        }

        if (!this.isOnline) {
            this.showWarning('Client is offline. Cannot load directory.');
            return;
        }

        this.showLoading();
        this.currentPath = path || 'C:\\';
        this.updateBreadcrumb();

        try {
            const response = await this.apiRequest('file_list', {
                path: path,
                page: 1,
                page_size: 100,
                sort: this.sortBy,
                order: this.sortOrder
            });

            if (response.error) {
                throw new Error(response.error);
            }

            if (response.status === 'pending') {
                this.pollCommand(response.command_id, 'list');
            } else {
                this.displayFiles(response);
                this.hideLoading();
            }
        } catch (error) {
            console.error('Error loading directory:', error);
            this.showError('Failed to load directory: ' + error.message);
            this.hideLoading();
        }
    }

    updateBreadcrumb() {
        const breadcrumb = document.getElementById('breadcrumb');
        if (!breadcrumb) return;

        const parts = this.currentPath.split('\\').filter(p => p);
        let html = '';
        let currentPath = '';

        parts.forEach((part, index) => {
            currentPath += (currentPath ? '\\' : '') + part;
            html += `<span class="text-gray-400">\\</span>`;
            if (index === parts.length - 1) {
                html += `<span class="text-yellow-400">${part}</span>`;
            } else {
                html += `<button onclick="fileManager.navigateTo('${currentPath}')" 
                          class="text-blue-400 hover:text-blue-300 hover:underline">${part}</button>`;
            }
        });

        breadcrumb.innerHTML = html || 'C:\\';
    }

    async pollCommand(commandId, actionType) {
        const maxAttempts = 30;
        let attempts = 0;

        const poll = async () => {
            attempts++;
            if (attempts > maxAttempts) {
                this.showError('Command timeout');
                this.hideLoading();
                return;
            }

            try {
                const response = await fetch(`?get_command_result&command_id=${commandId}`);
                const data = await response.json();

                if (data.status === 'completed') {
                    this.handleCommandResult(data, actionType);
                    this.hideLoading();
                } else if (data.status === 'pending') {
                    setTimeout(poll, 1000);
                } else {
                    this.showError('Command failed: ' + (data.error || 'Unknown error'));
                    this.hideLoading();
                }
            } catch (error) {
                console.error('Poll error:', error);
                setTimeout(poll, 1000);
            }
        };

        poll();
    }

    handleCommandResult(data, actionType) {
        try {
            const result = data.result || {};

            switch (actionType) {
                case 'list':
                    this.displayFiles(result);
                    break;
                case 'search':
                    this.displaySearchResults(result);
                    break;
                case 'upload':
                    this.showSuccess('Files uploaded successfully');
                    this.refresh();
                    break;
                case 'delete':
                    this.showSuccess('Files deleted successfully');
                    this.refresh();
                    break;
                case 'create':
                    this.showSuccess('Item created successfully');
                    this.refresh();
                    break;
                case 'rename':
                    this.showSuccess('Item renamed successfully');
                    this.refresh();
                    break;
                case 'copy':
                case 'move':
                    this.showSuccess(`Item ${actionType}d successfully`);
                    this.refresh();
                    break;
                case 'properties':
                    this.showPropertiesModal(result);
                    break;
                default:
                    console.log('Command result:', result);
            }
        } catch (error) {
            console.error('Error handling command result:', error);
            this.showError('Failed to process command result');
        }
    }

    displayFiles(data) {
        const container = document.getElementById('file-list');
        const emptyState = document.getElementById('empty-state');
        const statistics = document.getElementById('statistics');

        if (!container || !data) return;

        // Check if we have files or directories
        const hasFiles = data.files && data.files.length > 0;
        const hasDirs = data.directories && data.directories.length > 0;

        if (!hasFiles && !hasDirs) {
            container.classList.add('hidden');
            emptyState.classList.remove('hidden');
        } else {
            container.classList.remove('hidden');
            emptyState.classList.add('hidden');

            let html = '';

            // Directories first
            if (data.directories) {
                data.directories.forEach(dir => {
                    html += this.createFileItem(dir, true);
                });
            }

            // Files
            if (data.files) {
                data.files.forEach(file => {
                    html += this.createFileItem(file, false);
                });
            }

            container.innerHTML = html;
        }

        // Update statistics
        if (data.statistics && statistics) {
            statistics.classList.remove('hidden');
            document.getElementById('total-files').textContent = data.statistics.total_files || 0;
            document.getElementById('total-folders').textContent = data.statistics.total_folders || 0;
            document.getElementById('total-size').textContent = data.statistics.total_size_human || '0 B';
            document.getElementById('free-space').textContent = data.statistics.free_space_human || '0 B';
        }
    }

    createFileItem(item, isFolder) {
        const icon = isFolder ? 'fa-folder text-blue-400' : this.getFileIcon(item.extension);
        const size = isFolder ? '' : `• ${item.size_human || '0 B'}`;
        const modified = item.modified ? new Date(item.modified).toLocaleDateString() : '';
        const name = this.escapeHtml(item.name || item.path || 'Unknown');

        return `
            <div class="file-item" 
                 data-path="${name}" 
                 data-type="${isFolder ? 'folder' : 'file'}"
                 onclick="fileManager.selectFile('${name}', event)"
                 ondblclick="fileManager.${isFolder ? 'openFolder' : 'openFile'}('${name}')">
                <div class="file-icon">
                    <i class="fas ${icon} text-2xl"></i>
                </div>
                <div class="text-sm truncate mb-1" title="${name}">
                    ${name}
                </div>
                <div class="text-xs text-gray-500 truncate">
                    ${modified} ${size}
                </div>
            </div>
        `;
    }

    getFileIcon(extension) {
        const icons = {
            '.txt': 'fa-file-alt text-gray-400',
            '.pdf': 'fa-file-pdf text-red-400',
            '.doc': 'fa-file-word text-blue-400',
            '.docx': 'fa-file-word text-blue-400',
            '.xls': 'fa-file-excel text-green-400',
            '.xlsx': 'fa-file-excel text-green-400',
            '.jpg': 'fa-file-image text-yellow-400',
            '.jpeg': 'fa-file-image text-yellow-400',
            '.png': 'fa-file-image text-yellow-400',
            '.zip': 'fa-file-archive text-purple-400',
            '.rar': 'fa-file-archive text-purple-400',
            '.exe': 'fa-cog text-red-400',
            '.mp3': 'fa-file-audio text-pink-400',
            '.mp4': 'fa-file-video text-indigo-400'
        };
        return icons[extension?.toLowerCase()] || 'fa-file text-gray-400';
    }

    async apiRequest(action, data = {}) {
        if (!this.selectedClient) {
            throw new Error('No client selected');
        }

        const formData = new FormData();
        formData.append('action', action);
        formData.append('client_id', this.selectedClient);

        // Add data to form
        for (const [key, value] of Object.entries(data)) {
            if (value !== undefined && value !== null) {
                if (typeof value === 'object') {
                    formData.append(key, JSON.stringify(value));
                } else {
                    formData.append(key, String(value));
                }
            }
        }

        try {
            const response = await fetch('../api.php', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Secret-Token': '1'
                }
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            return result;
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }

    selectFile(filename, event) {
        const path = `${this.currentPath}\\${filename}`.replace(/\\\\/g, '\\');
        
        if (event.ctrlKey || event.metaKey) {
            // Multiple selection with Ctrl/Cmd
            if (this.selectedFiles.has(path)) {
                this.selectedFiles.delete(path);
            } else {
                this.selectedFiles.add(path);
            }
        } else {
            // Single selection
            this.selectedFiles.clear();
            this.selectedFiles.add(path);
        }

        this.updateSelectionUI();
        event.stopPropagation();
    }

    updateSelectionUI() {
        document.querySelectorAll('.file-item').forEach(item => {
            const path = `${this.currentPath}\\${item.dataset.path}`.replace(/\\\\/g, '\\');
            if (this.selectedFiles.has(path)) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        });
    }

    openFolder(folderName) {
        const newPath = `${this.currentPath}\\${folderName}`.replace(/\\\\/g, '\\');
        this.loadDirectory(newPath);
    }

    openFile(filename) {
        const filePath = `${this.currentPath}\\${filename}`.replace(/\\\\/g, '\\');
        
        this.apiRequest('file_download', {
            path: filePath
        }).then(response => {
            if (response.status === 'pending') {
                this.pollCommand(response.command_id, 'download');
                this.showInfo('Download started for: ' + filename);
            }
        }).catch(error => {
            this.showError('Failed to start download: ' + error.message);
        });
    }

    async downloadFile() {
        if (this.selectedFiles.size === 0) {
            this.showError('No files selected');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot download files.');
            return;
        }

        for (const filePath of this.selectedFiles) {
            try {
                const response = await this.apiRequest('file_download', {
                    path: filePath
                });

                if (response.status === 'pending') {
                    this.pollCommand(response.command_id, 'download');
                }
            } catch (error) {
                console.error('Download error:', error);
                this.showError('Download failed for: ' + filePath.split('\\').pop());
            }
        }

        this.showInfo('Download(s) started');
    }

    showRenameDialog() {
        if (this.selectedFiles.size !== 1) {
            this.showError('Please select exactly one item to rename');
            return;
        }

        const oldPath = Array.from(this.selectedFiles)[0];
        const oldName = oldPath.split('\\').pop();
        
        document.getElementById('rename-input').value = oldName;
        this.selectedFileForRename = oldPath;
        
        this.showModal('rename-modal');
    }

    async confirmRename() {
        const newName = document.getElementById('rename-input').value.trim();
        if (!newName) {
            this.showError('Please enter a new name');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot rename.');
            return;
        }

        const oldPath = this.selectedFileForRename;
        const newPath = oldPath.replace(/[^\\]*$/, newName);

        try {
            const response = await this.apiRequest('file_rename', {
                old_path: oldPath,
                new_path: newPath
            });

            if (response.status === 'success') {
                this.closeModal('rename-modal');
                this.pollCommand(response.command_id, 'rename');
            } else {
                this.showError('Rename failed: ' + (response.error || 'Unknown error'));
            }
        } catch (error) {
            this.showError('Rename failed: ' + error.message);
        }
    }

    createFolder() {
        this.showModal('new-folder-modal');
    }

    async confirmCreateFolder() {
        const folderName = document.getElementById('folder-name-input').value.trim();
        if (!folderName) {
            this.showError('Please enter a folder name');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot create folder.');
            return;
        }

        const path = `${this.currentPath}\\${folderName}`.replace(/\\\\/g, '\\');

        try {
            const response = await this.apiRequest('file_create', {
                path: path,
                type: 'folder'
            });

            if (response.status === 'success') {
                this.closeModal('new-folder-modal');
                this.pollCommand(response.command_id, 'create');
                document.getElementById('folder-name-input').value = '';
            } else {
                this.showError('Create folder failed: ' + (response.error || 'Unknown error'));
            }
        } catch (error) {
            this.showError('Create folder failed: ' + error.message);
        }
    }

    createFile() {
        const fileName = prompt('Enter file name:', 'newfile.txt');
        if (!fileName) return;

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot create file.');
            return;
        }

        const path = `${this.currentPath}\\${fileName}`.replace(/\\\\/g, '\\');

        this.apiRequest('file_create', {
            path: path,
            type: 'file'
        }).then(response => {
            if (response.status === 'success') {
                this.pollCommand(response.command_id, 'create');
            } else {
                this.showError('Create file failed: ' + (response.error || 'Unknown error'));
            }
        }).catch(error => {
            this.showError('Create file failed: ' + error.message);
        });
    }

    uploadFile() {
        this.uploadQueue = [];
        const queueElement = document.getElementById('upload-queue');
        if (queueElement) queueElement.innerHTML = '';
        this.showModal('upload-modal');
    }

    addFilesToQueue(files) {
        files.forEach(file => {
            this.uploadQueue.push({
                file: file,
                progress: 0,
                uploaded: false
            });

            this.updateUploadQueueUI();
        });
    }

    updateUploadQueueUI() {
        const queue = document.getElementById('upload-queue');
        if (!queue) return;

        queue.innerHTML = '';
        
        this.uploadQueue.forEach((item, index) => {
            const div = document.createElement('div');
            div.className = 'flex items-center justify-between p-3 bg-gray-800/50 rounded-lg';
            div.innerHTML = `
                <div class="flex items-center gap-3">
                    <i class="fas fa-file text-gray-400"></i>
                    <div>
                        <div class="text-sm truncate" style="max-width: 200px">${item.file.name}</div>
                        <div class="text-xs text-gray-500">${this.formatBytes(item.file.size)}</div>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <div class="w-24 h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div class="h-full bg-yellow-500 transition-all" 
                             style="width: ${item.progress}%"></div>
                    </div>
                    <button onclick="fileManager.removeFromQueue(${index})" 
                            class="text-gray-400 hover:text-red-400">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            queue.appendChild(div);
        });
    }

    removeFromQueue(index) {
        this.uploadQueue.splice(index, 1);
        this.updateUploadQueueUI();
    }

    async startUpload() {
        if (this.uploadQueue.length === 0) {
            this.showError('No files to upload');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot upload files.');
            return;
        }

        this.closeModal('upload-modal');
        this.showUploadProgress();

        for (let i = 0; i < this.uploadQueue.length; i++) {
            const item = this.uploadQueue[i];
            await this.uploadFileDirect(item.file, i);
        }

        this.hideUploadProgress();
        this.showSuccess('All files uploaded successfully');
        this.refresh();
        this.uploadQueue = [];
    }

    async uploadFileDirect(file, index) {
        const formData = new FormData();
        formData.append('action', 'file_upload');
        formData.append('client_id', this.selectedClient);
        formData.append('path', this.currentPath);
        formData.append('file', file);

        try {
            const response = await fetch('../api.php', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Secret-Token': '1'
                }
            });

            if (!response.ok) {
                throw new Error(`Upload failed: ${response.status}`);
            }

            const result = await response.json();
            
            // Update progress
            this.uploadQueue[index].progress = 100;
            this.uploadQueue[index].uploaded = true;
            this.updateUploadProgress();

            return result;
        } catch (error) {
            console.error('Upload error:', error);
            this.showError(`Failed to upload ${file.name}`);
            return null;
        }
    }

    updateUploadProgress() {
        const totalProgress = this.uploadQueue.reduce((sum, item) => sum + item.progress, 0) / this.uploadQueue.length;
        
        const progressBar = document.getElementById('upload-progress-bar');
        const progressText = document.getElementById('upload-progress-text');
        
        if (progressBar) progressBar.style.width = `${totalProgress}%`;
        if (progressText) progressText.textContent = `${Math.round(totalProgress)}%`;
    }

    showUploadProgress() {
        const progressElement = document.getElementById('upload-progress');
        if (progressElement) progressElement.classList.remove('hidden');
    }

    hideUploadProgress() {
        const progressElement = document.getElementById('upload-progress');
        if (progressElement) progressElement.classList.add('hidden');
    }

    async deleteFile() {
        if (this.selectedFiles.size === 0) {
            this.showError('No files selected');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot delete files.');
            return;
        }

        if (!confirm(`Delete ${this.selectedFiles.size} item(s)? This action cannot be undone.`)) {
            return;
        }

        const paths = Array.from(this.selectedFiles);

        try {
            const response = await this.apiRequest('file_delete', {
                paths: paths
            });

            if (response.status === 'success') {
                this.pollCommand(response.command_id, 'delete');
                this.selectedFiles.clear();
            } else {
                this.showError('Delete failed: ' + (response.error || 'Unknown error'));
            }
        } catch (error) {
            this.showError('Delete failed: ' + error.message);
        }
    }

    copyFile() {
        if (this.selectedFiles.size === 0) {
            this.showError('No files selected');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot copy files.');
            return;
        }
        
        const sourcePath = Array.from(this.selectedFiles)[0];
        const destPath = prompt('Enter destination path:', this.currentPath);
        
        if (!destPath) return;

        this.apiRequest('file_copy', {
            source_path: sourcePath,
            dest_path: destPath
        }).then(response => {
            if (response.status === 'success') {
                this.pollCommand(response.command_id, 'copy');
            } else {
                this.showError('Copy failed: ' + (response.error || 'Unknown error'));
            }
        }).catch(error => {
            this.showError('Copy failed: ' + error.message);
        });
    }

    moveFile() {
        if (this.selectedFiles.size === 0) {
            this.showError('No files selected');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot move files.');
            return;
        }
        
        const sourcePath = Array.from(this.selectedFiles)[0];
        const destPath = prompt('Enter destination path:', this.currentPath);
        
        if (!destPath) return;

        this.apiRequest('file_move', {
            source_path: sourcePath,
            dest_path: destPath
        }).then(response => {
            if (response.status === 'success') {
                this.pollCommand(response.command_id, 'move');
            } else {
                this.showError('Move failed: ' + (response.error || 'Unknown error'));
            }
        }).catch(error => {
            this.showError('Move failed: ' + error.message);
        });
    }

    async search() {
        const pattern = document.getElementById('search-input').value;
        const searchType = document.getElementById('search-type').value;

        if (!pattern.trim()) {
            this.showError('Please enter search pattern');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot search.');
            return;
        }

        try {
            const response = await this.apiRequest('file_search', {
                root_path: this.currentPath,
                pattern: pattern,
                search_type: searchType,
                max_results: 100
            });

            if (response.status === 'success') {
                this.pollCommand(response.command_id, 'search');
            } else {
                this.showError('Search failed: ' + (response.error || 'Unknown error'));
            }
        } catch (error) {
            this.showError('Search failed: ' + error.message);
        }
    }

    displaySearchResults(data) {
        const container = document.getElementById('file-list');
        if (!container || !data.results) return;

        if (data.results.length === 0) {
            container.innerHTML = '<div class="text-center py-8 text-gray-400">No results found</div>';
            return;
        }

        let html = '';
        data.results.forEach(result => {
            html += this.createFileItem({
                name: result.path,
                extension: result.extension,
                size_human: result.size_human,
                modified: result.modified
            }, result.type === 'folder');
        });

        container.innerHTML = html;
    }

    async showProperties() {
        if (this.selectedFiles.size !== 1) {
            this.showError('Please select exactly one item');
            return;
        }

        if (!this.isOnline) {
            this.showError('Client is offline. Cannot get properties.');
            return;
        }

        const path = Array.from(this.selectedFiles)[0];

        try {
            const response = await this.apiRequest('file_properties', {
                path: path
            });

            if (response.status === 'success') {
                this.pollCommand(response.command_id, 'properties');
            } else {
                this.showError('Failed to get properties: ' + (response.error || 'Unknown error'));
            }
        } catch (error) {
            this.showError('Failed to get properties: ' + error.message);
        }
    }

    showPropertiesModal(data) {
        const container = document.getElementById('properties-content');
        if (!container) return;

        let html = `
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <div class="text-sm text-gray-400">Name</div>
                        <div class="font-medium">${data.name || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400">Type</div>
                        <div class="font-medium">${data.type || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400">Size</div>
                        <div class="font-medium">${data.size_human || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400">Modified</div>
                        <div class="font-medium">${data.modified ? new Date(data.modified).toLocaleString() : 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400">Path</div>
                        <div class="font-medium truncate" title="${data.path}">${data.path || 'N/A'}</div>
                    </div>
                    <div>
                        <div class="text-sm text-gray-400">Attributes</div>
                        <div class="font-medium">${data.attributes || 'N/A'}</div>
                    </div>
                </div>
        `;

        if (data.hash) {
            html += `
                <div class="border-t border-gray-700 pt-4">
                    <div class="text-sm text-gray-400 mb-2">Hash</div>
                    <div class="font-mono text-sm bg-gray-800 p-3 rounded-lg overflow-x-auto">
                        ${data.hash}
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;
        this.showModal('properties-modal');
    }

    navigateTo(path) {
        this.loadDirectory(path);
    }

    refresh() {
        if (this.selectedClient && this.isOnline) {
            this.loadDirectory(this.currentPath);
        }
    }

    setView(view) {
        this.currentView = view;
        const container = document.getElementById('file-list');
        if (!container) return;
        
        if (view === 'grid') {
            container.classList.remove('grid-cols-1');
            container.classList.add('file-grid');
            const gridBtn = document.getElementById('view-grid');
            const listBtn = document.getElementById('view-list');
            if (gridBtn) gridBtn.classList.add('bg-yellow-500/20', 'text-yellow-400');
            if (listBtn) listBtn.classList.remove('bg-yellow-500/20', 'text-yellow-400');
        } else {
            container.classList.remove('file-grid');
            container.classList.add('grid-cols-1');
            const listBtn = document.getElementById('view-list');
            const gridBtn = document.getElementById('view-grid');
            if (listBtn) listBtn.classList.add('bg-yellow-500/20', 'text-yellow-400');
            if (gridBtn) gridBtn.classList.remove('bg-yellow-500/20', 'text-yellow-400');
        }
    }

    sortFiles() {
        const sortBy = document.getElementById('sort-by');
        const sortOrder = document.getElementById('sort-order');
        
        if (sortBy) this.sortBy = sortBy.value;
        if (sortOrder) this.sortOrder = sortOrder.value;
        
        this.refresh();
    }

    showContextMenu(event) {
        const menu = document.getElementById('context-menu');
        if (menu) {
            menu.style.display = 'block';
            menu.style.left = `${event.pageX}px`;
            menu.style.top = `${event.pageY}px`;
        }
        event.preventDefault();
    }

    hideContextMenu() {
        const menu = document.getElementById('context-menu');
        if (menu) menu.style.display = 'none';
    }

    showLoading() {
        const loader = document.getElementById('loading-overlay');
        if (loader) loader.classList.remove('hidden');
    }

    hideLoading() {
        const loader = document.getElementById('loading-overlay');
        if (loader) loader.classList.add('hidden');
    }

    showModal(id) {
        const modal = document.getElementById(id);
        if (modal) modal.classList.remove('hidden');
    }

    closeModal(id) {
        const modal = document.getElementById(id);
        if (modal) modal.classList.add('hidden');
    }

    showError(message) {
        console.error('Error:', message);
        alert('❌ Error: ' + message);
    }

    showWarning(message) {
        console.warn('Warning:', message);
        alert('⚠️ Warning: ' + message);
    }

    showSuccess(message) {
        console.log('Success:', message);
        alert('✅ Success: ' + message);
    }

    showInfo(message) {
        console.log('Info:', message);
        // You can implement a toast notification here
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions
function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('hidden');
}

// Initialize file manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Check if we have a selected client
    if (SELECTED_CLIENT) {
        window.fileManager = new FileManager();
    }
});