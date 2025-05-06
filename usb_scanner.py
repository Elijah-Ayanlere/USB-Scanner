import os
import sys
import platform
import time
import hashlib
import psutil
import colorama
import shutil
from colorama import Fore, Style

# Initialize colorama
colorama.init()

class USBDefender:
    def __init__(self):
        """Initialize the USB scanner with common virus file signatures."""
        self.system = platform.system()
        self.previous_drives = set()
        
        # Platform-specific suspicious file extensions
        if self.system == "Windows":
            self.suspicious_extensions = {
                '.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.dll', 
                '.pif', '.com', '.ps1', '.vbe', '.wsf', '.wsh', '.hta', '.msi',
                '.ade', '.adp', '.app', '.cpl', '.crt', '.fxp', '.hlp', '.inf',
                '.ins', '.isp', '.jse', '.lnk', '.msc', '.mst', '.pcd', '.reg',
                '.scf', '.sct', '.shb', '.shs', '.xnk'
            }
        else:  # Linux and macOS
            self.suspicious_extensions = {
                '.exe', '.bat', '.cmd', '.sh', '.js', '.jar', '.dll', '.bin',
                '.py', '.perl', '.rb', '.bash', '.ksh', '.csh', '.so', '.dylib',
                '.app', '.deb', '.rpm'
            }
        
        # Common malware patterns across all platforms
        self.suspicious_filenames = [
            'autorun.inf', 'desktop.ini', 'thumbs.db', '.DS_Store',
            'launch.command', 'install.command', 'setup.command',
            'payload', 'rootkit', 'backdoor', 'trojan', 'spyware'
        ]
        
        # Some common malware file signatures (MD5 hashes)
        self.known_malware_hashes = {
            "e44a15482547e6bf0f91f05b1946b75d": "Trojan.Generic",
            "7b201f3e8bf8643d8387c17379610d9a": "Backdoor.Generic",
            "5f3932c7096b6b0f9142eeb022bdfdcd": "Worm.Generic",
            "84c82835a5d21bbcf75a61706d8ab549": "Virus.Generic", 
            "aee20f9188a5c3954623583c6b0e6b0b": "Rootkit.Generic",
            "3eb86b7b067c29f59edd9f96d2aaa528": "Keylogger.Generic",
        }
        
        # Initialize scan statistics
        self.total_drives_scanned = 0
        self.total_files_scanned = 0
        self.total_threats_found = 0

    def get_current_drives(self):
        """Get a set of currently connected removable drives."""
        removable_drives = set()
        
        if self.system == "Windows":
            for d in psutil.disk_partitions():
                # On Windows, removable drives typically have 'removable' in opts
                # or are mounted to drive letters beyond C:
                if ('removable' in d.opts.lower() or 
                    (d.device[0].upper() >= 'D' and d.device[0].upper() <= 'Z')):
                    try:
                        # Check if it's really a removable drive
                        import ctypes
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(d.device + "\\")
                        # 2 = DRIVE_REMOVABLE
                        if drive_type == 2:
                            removable_drives.add(d.device)
                    except:
                        # If we can't determine for sure, add it if it's not C:
                        if not d.device.startswith(('C:')):
                            removable_drives.add(d.device)
        
        elif self.system == "Linux":
            # Check /media/ (Ubuntu-style) and /run/media/$USER/ (Fedora-style)
            username = os.getenv('USER', '')
            for d in psutil.disk_partitions():
                if (d.mountpoint.startswith('/media/') or 
                    d.mountpoint.startswith(f'/run/media/{username}/') or
                    '/usb' in d.mountpoint.lower()):
                    removable_drives.add(d.mountpoint)
                
                # Also check /mnt/ if it contains removable media keywords
                if d.mountpoint.startswith('/mnt/'):
                    mount_name = os.path.basename(d.mountpoint).lower()
                    if any(keyword in mount_name for keyword in ['usb', 'removable', 'thumb', 'flash', 'external']):
                        removable_drives.add(d.mountpoint)
        
        elif self.system == "Darwin":  # macOS
            for d in psutil.disk_partitions():
                # Most external drives on macOS are mounted in /Volumes/
                # Exclude the main system drive
                if (d.mountpoint.startswith('/Volumes/') and 
                    not d.mountpoint.endswith('Macintosh HD') and
                    'Macintosh HD' not in d.mountpoint):
                    removable_drives.add(d.mountpoint)
        
        else:
            print(f"{Fore.RED}Unsupported operating system: {self.system}{Style.RESET_ALL}")
        
        return removable_drives

    def calculate_file_hash(self, file_path):
        """Calculate MD5 hash of a file."""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
            return file_hash.hexdigest()
        except (IOError, PermissionError) as e:
            return None

    def check_file_type(self, file_path):
        """Use magic to determine the file type."""
        try:
            # Try to import the magic library
            try:
                import magic
            except ImportError:
                try:
                    # On Windows, python-magic-bin might be installed instead
                    from magic import magic
                except ImportError:
                    print(f"{Fore.RED}Error: Required library 'python-magic' not found.{Style.RESET_ALL}")
                    print(f"Please install it using: pip install python-magic")
                    print(f"On Windows, you may need: pip install python-magic-bin")
                    return "Unknown"
                    
            file_type = magic.from_file(file_path)
            return file_type
        except Exception as e:
            # Handle cases where magic fails
            try:
                # Fallback method for file type detection
                import mimetypes
                mime_type, _ = mimetypes.guess_type(file_path)
                if mime_type:
                    return mime_type
            except:
                pass
            return "Unknown"

    def scan_file(self, file_path):
        """Scan a single file for suspicious characteristics."""
        try:
            # Check if it's a hidden file
            filename = os.path.basename(file_path)
            file_lower = filename.lower()
            
            # Check if filename matches known suspicious patterns
            if file_lower in [name.lower() for name in self.suspicious_filenames]:
                return True, f"Suspicious filename: {filename}"
            
            if filename.startswith('.') and self.system != "Windows":
                # Hidden files in Unix-like systems
                if len(filename) > 1 and not filename.startswith('..'):
                    # Ignore . and .. directory entries
                    return True, "Hidden file"
            
            # Special case for Windows hidden attribute
            if self.system == "Windows" and os.path.exists(file_path):
                try:
                    import stat
                    attrs = os.stat(file_path).st_file_attributes
                    if attrs & stat.FILE_ATTRIBUTE_HIDDEN:
                        return True, "Hidden file (Windows attribute)"
                except:
                    pass
            
            # Check if file has suspicious extension
            _, ext = os.path.splitext(file_path.lower())
            if ext in self.suspicious_extensions:
                # Further analyze executable files
                file_hash = self.calculate_file_hash(file_path)
                if file_hash:
                    if file_hash in self.known_malware_hashes:
                        return True, f"MALWARE DETECTED: {self.known_malware_hashes[file_hash]}"
                    
                    # For executable files, do further checks
                    file_type = self.check_file_type(file_path)
                    if file_type:
                        if any(exe_sig in file_type.lower() for exe_sig in 
                               ["executable", "elf", "x86", "x64", "mach-o", "pe32", 
                                "windows", "ms-dos", "java", "script"]):
                            return True, f"Executable file ({file_type})"
                
                return True, f"Suspicious extension: {ext}"
            
            # Check file size - unusually small executables can be suspicious
            try:
                file_size = os.path.getsize(file_path)
                if ext in ['.exe', '.dll'] and file_size < 5000:
                    return True, f"Suspicious: Very small executable ({file_size} bytes)"
            except:
                pass
                
            # Additional check for script files that might not have extensions
            if not ext and os.access(file_path, os.X_OK):
                # Executable without extension - check first few bytes
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        first_line = f.readline().strip()
                        if first_line.startswith('#!') and ('/bin/' in first_line or '/usr/' in first_line):
                            return True, f"Script file (shebang: {first_line})"
                except:
                    pass
            
            return False, ""
        except Exception as e:
            return False, ""

    def scan_drive(self, drive_path):
        """Scan a drive for suspicious files."""
        print(f"\n{Fore.GREEN}Scanning drive: {drive_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
        
        suspicious_files = []
        all_files = []
        total_size = 0
        scan_start_time = time.time()
        files_count = 0
        scan_errors = 0
        
        try:
            # Verify the drive is still accessible
            if not os.path.exists(drive_path):
                print(f"{Fore.RED}Error: Drive {drive_path} is no longer accessible.{Style.RESET_ALL}")
                return False
            
            # Print scanning animation
            print(f"Scanning in progress", end="")
            animation_chars = ['|', '/', '-', '\\']
            animation_idx = 0
            
            for root, dirs, files in os.walk(drive_path):
                # Skip system directories that might cause issues
                if self.system == "Windows":
                    dirs[:] = [d for d in dirs if not d.startswith('System Volume Information') and d not in ['System Volume Information']]
                else:
                    dirs[:] = [d for d in dirs if not d.startswith('.Trash')]
                
                # Update animation
                if files_count % 10 == 0:
                    print(f"\rScanning in progress {animation_chars[animation_idx]} ({files_count} files)", end="")
                    animation_idx = (animation_idx + 1) % len(animation_chars)
                
                for file in files:
                    files_count += 1
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, drive_path)
                    
                    try:
                        file_size = os.path.getsize(file_path)
                        total_size += file_size
                        
                        # Store basic file info
                        file_info = {
                            'path': rel_path,
                            'size': file_size,
                            'suspicious': False,
                            'reason': ""
                        }
                        
                        # Check if file is suspicious
                        is_suspicious, reason = self.scan_file(file_path)
                        if is_suspicious:
                            file_info['suspicious'] = True
                            file_info['reason'] = reason
                            suspicious_files.append(file_info)
                            self.total_threats_found += 1
                        
                        all_files.append(file_info)
                        self.total_files_scanned += 1
                    except (IOError, PermissionError) as e:
                        scan_errors += 1
                        if scan_errors <= 5:  # Limit error messages to avoid spam
                            print(f"\n{Fore.RED}Error accessing {rel_path}: {str(e)}{Style.RESET_ALL}")
                        elif scan_errors == 6:
                            print(f"\n{Fore.RED}Additional access errors encountered. Suppressing further error messages.{Style.RESET_ALL}")
            
            # Clear the animation line
            print("\r" + " " * 70 + "\r", end="")
            
        except Exception as e:
            print(f"\n{Fore.RED}Error scanning drive {drive_path}: {str(e)}{Style.RESET_ALL}")
        
        scan_time = time.time() - scan_start_time
        
        # Update stats
        self.total_drives_scanned += 1
        
        # Print summary
        print(f"\n{Fore.CYAN}Scan Summary for {drive_path}:{Style.RESET_ALL}")
        print(f"Scan completed in: {scan_time:.2f} seconds")
        print(f"Total files: {len(all_files)}")
        print(f"Total size: {self.format_size(total_size)}")
        print(f"Access errors encountered: {scan_errors}")
        print(f"Suspicious files: {len(suspicious_files)}")
        
        # Return if there were any threats
        has_threats = len(suspicious_files) > 0
        
        # If threats were found, ask if the user wants to quarantine them
        if has_threats:
            print(f"\n{Fore.RED}WARNING: Found {len(suspicious_files)} suspicious files!{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Would you like to quarantine these files? (y/n){Style.RESET_ALL}")
            choice = input().strip().lower()
            if choice == 'y':
                self.quarantine_files(drive_path, suspicious_files)
            
            # Ask if user wants to export a report
            print(f"\n{Fore.YELLOW}Would you like to export a detailed report? (y/n){Style.RESET_ALL}")
            report_choice = input().strip().lower()
            if report_choice == 'y':
                self.export_report(drive_path, suspicious_files, all_files, scan_time)
        
        return has_threats

    def format_size(self, size_bytes):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    def quarantine_files(self, drive_path, suspicious_files):
        """Move suspicious files to a quarantine folder."""
        quarantine_dir = os.path.join(os.path.expanduser("~"), "USBDefender_Quarantine")
        
        # Create quarantine directory if it doesn't exist
        if not os.path.exists(quarantine_dir):
            try:
                os.makedirs(quarantine_dir)
                print(f"{Fore.YELLOW}Created quarantine directory: {quarantine_dir}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error creating quarantine directory: {str(e)}{Style.RESET_ALL}")
                return
        
        # Create subfolder for this scan
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        scan_quarantine = os.path.join(quarantine_dir, f"scan_{timestamp}")
        try:
            os.makedirs(scan_quarantine)
        except Exception as e:
            print(f"{Fore.RED}Error creating scan quarantine directory: {str(e)}{Style.RESET_ALL}")
            return
        
        # Create a log file
        log_path = os.path.join(scan_quarantine, "quarantine_log.txt")
        try:
            with open(log_path, 'w') as log_file:
                log_file.write(f"USBDefender Quarantine Log - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Source drive: {drive_path}\n")
                log_file.write("-" * 60 + "\n\n")
                
                # Move each suspicious file
                moved_count = 0
                for file_info in suspicious_files:
                    original_path = os.path.join(drive_path, file_info['path'])
                    
                    # Create directory structure in quarantine
                    rel_dir = os.path.dirname(file_info['path'])
                    target_dir = os.path.join(scan_quarantine, rel_dir)
                    if rel_dir and not os.path.exists(target_dir):
                        try:
                            os.makedirs(target_dir)
                        except Exception as e:
                            log_file.write(f"ERROR creating directory {rel_dir}: {str(e)}\n")
                            continue
                    
                    # Move file to quarantine
                    target_path = os.path.join(scan_quarantine, file_info['path'])
                    try:
                        import shutil
                        shutil.copy2(original_path, target_path)
                        
                        # Now try to remove the original
                        try:
                            os.remove(original_path)
                            log_file.write(f"MOVED: {file_info['path']} -> {target_path}\n")
                            log_file.write(f"  Reason: {file_info['reason']}\n")
                            log_file.write(f"  Size: {self.format_size(file_info['size'])}\n\n")
                            moved_count += 1
                        except Exception as e:
                            log_file.write(f"COPIED ONLY (failed to delete original): {file_info['path']} -> {target_path}\n")
                            log_file.write(f"  Error: {str(e)}\n")
                            log_file.write(f"  Reason: {file_info['reason']}\n")
                            log_file.write(f"  Size: {self.format_size(file_info['size'])}\n\n")
                    except Exception as e:
                        log_file.write(f"ERROR quarantining {file_info['path']}: {str(e)}\n\n")
            
            print(f"{Fore.GREEN}Successfully quarantined {moved_count} of {len(suspicious_files)} suspicious files.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Quarantine location: {scan_quarantine}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}See log file for details: {log_path}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}Error during quarantine process: {str(e)}{Style.RESET_ALL}")

    def export_report(self, drive_path, suspicious_files, all_files, scan_time):
        """Export a detailed scan report to a file."""
        reports_dir = os.path.join(os.path.expanduser("~"), "USBDefender_Reports")
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(reports_dir):
            try:
                os.makedirs(reports_dir)
            except Exception as e:
                print(f"{Fore.RED}Error creating reports directory: {str(e)}{Style.RESET_ALL}")
                return None
        
        # Create report file
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        drive_name = os.path.basename(drive_path) if os.path.basename(drive_path) else drive_path.replace("\\", "_").replace("/", "_").replace(":", "")
        report_path = os.path.join(reports_dir, f"scan_report_{drive_name}_{timestamp}.txt")
        
        try:
            with open(report_path, 'w') as report:
                report.write(f"USBDefender Report - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                report.write(f"{'=' * 60}\n\n")
                report.write(f"Drive: {drive_path}\n")
                report.write(f"Scan duration: {scan_time:.2f} seconds\n")
                report.write(f"Files scanned: {len(all_files)}\n")
                report.write(f"Suspicious files: {len(suspicious_files)}\n\n")
                
                if suspicious_files:
                    report.write(f"SUSPICIOUS FILES\n")
                    report.write(f"{'=' * 60}\n")
                    for file_info in suspicious_files:
                        report.write(f"File: {file_info['path']}\n")
                        report.write(f"Size: {self.format_size(file_info['size'])}\n")
                        report.write(f"Reason: {file_info['reason']}\n")
                        report.write(f"{'-' * 40}\n")
                
                report.write(f"\nALL FILES\n")
                report.write(f"{'=' * 60}\n")
                for file_info in all_files:
                    status = "SUSPICIOUS" if file_info['suspicious'] else "OK"
                    report.write(f"{status} - {self.format_size(file_info['size'])} - {file_info['path']}\n")
                
            print(f"{Fore.GREEN}Report exported to: {report_path}{Style.RESET_ALL}")
            return report_path
        except Exception as e:
            print(f"{Fore.RED}Error exporting report: {str(e)}{Style.RESET_ALL}")
            return None

    def show_statistics(self):
        """Display overall scan statistics."""
        print(f"\n{Fore.CYAN}Overall Statistics:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
        print(f"Total drives scanned: {self.total_drives_scanned}")
        print(f"Total files scanned: {self.total_files_scanned}")
        print(f"Total threats found: {self.total_threats_found}")
        
    def monitor_drives(self):
        """Monitor for new drives and scan them when detected."""
        print(f"{Fore.CYAN}Starting drive monitoring...{Style.RESET_ALL}")
        self.previous_drives = self.get_current_drives()
        
        # Initial status message
        if not self.previous_drives:
            print(f"{Fore.YELLOW}No removable drives currently connected. Waiting for drives...{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Currently connected drives: {', '.join(self.previous_drives)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Would you like to scan these drives now? (y/n){Style.RESET_ALL}")
            choice = input().strip().lower()
            if choice == 'y':
                for drive in self.previous_drives:
                    has_threats = self.scan_drive(drive)
                    if has_threats:
                        print(f"{Fore.RED}WARNING: Suspicious files detected on {drive}!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}No threats detected on {drive}.{Style.RESET_ALL}")
        
        counter = 0
        try:
            while True:
                current_drives = self.get_current_drives()
                
                # Check for new drives
                new_drives = current_drives - self.previous_drives
                if new_drives:
                    print(f"{Fore.GREEN}New drive(s) detected: {', '.join(new_drives)}{Style.RESET_ALL}")
                    for drive in new_drives:
                        has_threats = self.scan_drive(drive)
                        if has_threats:
                            print(f"{Fore.RED}WARNING: Suspicious files detected on {drive}!{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.GREEN}No threats detected on {drive}.{Style.RESET_ALL}")
                
                # Check for removed drives
                removed_drives = self.previous_drives - current_drives
                if removed_drives:
                    print(f"{Fore.YELLOW}Drive(s) removed: {', '.join(removed_drives)}{Style.RESET_ALL}")
                
                # Periodically show status if no drives are connected
                counter += 1
                if counter >= 15 and not current_drives:  # About 30 seconds with 2-second sleep
                    print(f"{Fore.YELLOW}No removable drives currently connected. Still monitoring...{Style.RESET_ALL}")
                    counter = 0
                    
                    # Show statistics periodically
                    if self.total_drives_scanned > 0:
                        self.show_statistics()
                
                # Update previous drives
                self.previous_drives = current_drives
                
                # Wait before next check
                time.sleep(2)
        except KeyboardInterrupt:
            print(f"{Fore.CYAN}\nMonitoring stopped.{Style.RESET_ALL}")
            
            # Show final statistics
            if self.total_drives_scanned > 0:
                self.show_statistics()
                
            print(f"{Fore.CYAN}Thank you for using USBDefender!{Style.RESET_ALL}")


def check_dependencies():
    """Check if required dependencies are installed."""
    missing = []
    
    try:
        import psutil
    except ImportError:
        missing.append("psutil")
    
    try:
        import magic
    except ImportError:
        try:
            from magic import magic
        except ImportError:
            missing.append("python-magic or python-magic-bin")
    
    if missing:
        print(f"{Fore.RED}Error: Missing required dependencies: {', '.join(missing)}{Style.RESET_ALL}")
        print(f"Please install them using: pip install {' '.join(missing)}")
        print(f"On Windows, you may need: pip install python-magic-bin instead of python-magic")
        return False
    
    return True


def print_dynamic_banner():
    """Print a dynamically sized banner that adapts to terminal width."""
    # Get terminal size
    terminal_width, _ = shutil.get_terminal_size((80, 20))  # Default to 80x20 if can't determine
    
    # Define the banner text for USBDefender
    banner_lines = [
        "██╗   ██╗███████╗██████╗     ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ███████╗██████╗ ",
        "██║   ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗",
        "██║   ██║███████╗██████╔╝    ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝",
        "██║   ██║╚════██║██╔══██╗    ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗",
        "╚██████╔╝███████║██████╔╝    ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝███████╗██║  ██║",
        " ╚═════╝ ╚══════╝╚═════╝     ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝"
    ]
    
    # Calculate the width of the banner
    banner_width = max(len(line) for line in banner_lines)
    
    # If banner is wider than terminal, use a simpler banner
    if banner_width > terminal_width:
        simple_banner = [
            "┌─────────────────────┐",
            "│     USBDefender     │",
            "└─────────────────────┘"
        ]
        banner_width = max(len(line) for line in simple_banner)
        
        # Center the simple banner
        padding = (terminal_width - banner_width) // 2
        for line in simple_banner:
            print(f"{Fore.CYAN}{' ' * padding}{line}{Style.RESET_ALL}")
    else:
        # Center the full banner
        padding = (terminal_width - banner_width) // 2
        for line in banner_lines:
            print(f"{Fore.CYAN}{' ' * padding}{line}{Style.RESET_ALL}")
    
    # Print subtitle
    subtitle = "Advanced USB Drive Security & Malware Scanner"
    subtitle_padding = (terminal_width - len(subtitle)) // 2
    print()
    print(f"{Fore.YELLOW}{' ' * subtitle_padding}{subtitle}{Style.RESET_ALL}")
    
    # Print separator line
    separator = '═' * min(terminal_width, 80)  # Limit separator width to 80 or terminal width
    separator_padding = (terminal_width - min(terminal_width, 80)) // 2
    print(f"{Fore.YELLOW}{' ' * separator_padding}{separator}{Style.RESET_ALL}")
    
    # Print version and platform
    version_info = f"v1.0.0 | {platform.system()} {platform.release()}"
    version_padding = (terminal_width - len(version_info)) // 2
    print(f"{Fore.GREEN}{' ' * version_padding}{version_info}{Style.RESET_ALL}")
    print()


def display_help():
    """Display help information."""
    print(f"\n{Fore.CYAN}USBDefender Help{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'=' * 60}{Style.RESET_ALL}")
    print("USBDefender is a tool to protect your system from USB-based malware threats.")
    print("\nCommands:")
    print(f"  {Fore.GREEN}monitor{Style.RESET_ALL} - Start monitoring for new USB drives")
    print(f"  {Fore.GREEN}scan <drive_path>{Style.RESET_ALL} - Scan a specific drive")
    print(f"  {Fore.GREEN}list{Style.RESET_ALL} - List currently connected removable drives")
    print(f"  {Fore.GREEN}help{Style.RESET_ALL} - Show this help message")
    print(f"  {Fore.GREEN}exit{Style.RESET_ALL} - Exit the program")
    print("\nExamples:")
    if platform.system() == "Windows":
        print(f"  {Fore.GREEN}scan E:{Style.RESET_ALL} - Scan the E: drive")
    else:
        print(f"  {Fore.GREEN}scan /media/username/USB_DRIVE{Style.RESET_ALL} - Scan a USB drive")
    print(f"  {Fore.GREEN}monitor{Style.RESET_ALL} - Start continuous monitoring for new drives")


def main():
    """Main function to run the program."""
    # Print banner
    print_dynamic_banner()
    
    # Check for required dependencies
    if not check_dependencies():
        print(f"{Fore.YELLOW}USBDefender will continue but may have limited functionality.{Style.RESET_ALL}")
    
    # Create USB defender instance
    defender = USBDefender()
    
    # Check if running with arguments
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "monitor":
            defender.monitor_drives()
            return
        elif sys.argv[1].lower() == "scan" and len(sys.argv) > 2:
            drive_path = sys.argv[2]
            defender.scan_drive(drive_path)
            return
    
    # Interactive mode
    print(f"\n{Fore.CYAN}USBDefender interactive mode. Type 'help' for commands.{Style.RESET_ALL}")
    
    while True:
        try:
            command = input(f"\n{Fore.GREEN}USBDefender> {Style.RESET_ALL}").strip()
            
            if not command:
                continue
                
            parts = command.split()
            cmd = parts[0].lower()
            
            if cmd == "exit" or cmd == "quit":
                print(f"{Fore.CYAN}Exiting USBDefender. Stay safe!{Style.RESET_ALL}")
                break
                
            elif cmd == "help":
                display_help()
                
            elif cmd == "monitor":
                defender.monitor_drives()
                
            elif cmd == "scan":
                if len(parts) < 2:
                    print(f"{Fore.RED}Error: Please specify a drive path.{Style.RESET_ALL}")
                    print(f"Usage: scan <drive_path>")
                else:
                    drive_path = parts[1]
                    defender.scan_drive(drive_path)
                    
            elif cmd == "list":
                drives = defender.get_current_drives()
                if drives:
                    print(f"{Fore.CYAN}Currently connected removable drives:{Style.RESET_ALL}")
                    for drive in drives:
                        print(f"  {Fore.GREEN}• {drive}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}No removable drives currently connected.{Style.RESET_ALL}")
                    
            else:
                print(f"{Fore.RED}Unknown command: {cmd}{Style.RESET_ALL}")
                print(f"Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}Operation cancelled. Type 'exit' to quit.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{Fore.RED}Critical Error: {str(e)}{Style.RESET_ALL}")
        print(f"USBDefender has encountered an unexpected error and needs to exit.")
        # Create a crash log
        try:
            crash_dir = os.path.join(os.path.expanduser("~"), "USBDefender_Logs")
            if not os.path.exists(crash_dir):
                os.makedirs(crash_dir)
            
            crash_log = os.path.join(crash_dir, f"crash_{time.strftime('%Y%m%d_%H%M%S')}.txt")
            with open(crash_log, 'w') as f:
                f.write(f"USBDefender Crash Log - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"System: {platform.system()} {platform.release()}\n")
                f.write(f"Python: {platform.python_version()}\n")
                f.write(f"Error: {str(e)}\n\n")
                import traceback
                f.write(traceback.format_exc())
            
            print(f"{Fore.YELLOW}A crash log has been saved to: {crash_log}{Style.RESET_ALL}")
        except:
            pass