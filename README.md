
# USBDefender – USB Drive Malware Scanner & Auto-Monitor

A cross-platform USB malware scanner and defense tool with a modern GUI, automatic USB monitoring, quarantine, and detailed reports.

---

## 🚀 Features

- ✅ **Real-time USB monitoring**
- 🛡️ **Automatic scanning of inserted drives**
- 🧠 **Suspicious file detection** (extensions, hidden status, known hashes, executable content)
- 📁 **Quarantine infected files**
- 📊 **Detailed scan reports**
- 🎨 **Dark mode GUI using Tkinter**
- 🧩 **Cross-platform**: Works on **Windows**, **Linux**, and **macOS**

---

## 📦 Requirements

Make sure Python is installed. Then install these:

```bash
pip install psutil python-magic colorama
```

On **Windows**, install this instead of `python-magic`:

```bash
pip install python-magic-bin
```

---

## 🖥️ GUI Setup (usb_gui.py)

1. Clone or copy the files:
   - `usb_scanner.py` – core logic
   - `usb_gui.py` – GUI interface
   - Optionally, `usbdefender.ico` – custom icon for packaging

2. Launch the GUI:

On **Windows**

```bash
python usb_gui.py
```

On **MacOS/Linux**

```bash
python3 usb_gui.py
```

---

## 💻 Packaging as Standalone App

Use **PyInstaller** to bundle the app:

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --icon=usbdefender.ico usb_gui.py
```

- `.exe` for Windows will be in the `dist` folder.
- `.app` for macOS or ELF binary for Linux can be similarly generated.

---

## 🪟 Auto-Launch on USB Insert (Windows)

This method uses **Task Scheduler**:

### 🧑‍💻 Steps:

1. Open **Task Scheduler**.
2. Click **Create Task**.
3. In the **General** tab:
   - Name: `USBDefender AutoLaunch`
   - Check: `Run with highest privileges`
4. Go to **Triggers** → **New…**:
   - Begin task: `On an event`
   - Log: `Microsoft-Windows-DriverFrameworks-UserMode/Operational`
   - Source: `DriverFrameworks-UserMode`
   - Event ID: `2003`
5. **Actions** → **New…**:
   - Action: `Start a program`
   - Program/script: Browse and select your `usb_gui.exe`
6. Click OK. You're done ✅

---

## 🐧 Auto-Launch on USB Insert (Linux)

This uses **udev rules** and a bash script.

### 🧑‍💻 Step 1: Create udev Rule

```bash
sudo nano /etc/udev/rules.d/99-usbdefender.rules
```

Paste this:

```bash
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[b-z][0-9]", RUN+="/usr/local/bin/usbdefender-launch.sh"
```

### 🧑‍💻 Step 2: Create the Launcher Script

```bash
sudo nano /usr/local/bin/usbdefender-launch.sh
```

Paste:

```bash
#!/bin/bash
DISPLAY=:0
export DISPLAY
/usr/bin/python3 /home/YOUR_USERNAME/path/to/usb_gui.py
```

Make it executable:

```bash
sudo chmod +x /usr/local/bin/usbdefender-launch.sh
```

Reload udev rules:

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## 💡 How It Works

- Detects new removable drives using `psutil`
- Scans each file for:
  - Known malware hashes
  - Suspicious filenames or extensions
  - Hidden attributes
  - Executable code using `magic` file type checking
- Suspicious files can be:
  - Quarantined to a safe folder
  - Reported in detailed `.txt` reports

---

## 📊 GUI Overview

- **Dropdown:** Select connected USB drive
- **Scan Drive:** Scans the selected drive
- **Start Monitoring:** Begins real-time detection (button toggles to “Stop Monitoring”)
- **Export Report:** Saves a report of last scan
- **Log Output:** Shows live logs with green hacker-style output
- **Status Bar:** Shows current status (e.g., monitoring, scanning)

---

## ❌ Uninstallation

- Delete `usb_gui.py`, `usb_scanner.py`, and any packaged `.exe` or `.app` files.
- Remove Task Scheduler task or udev rules if set up.

---

## 🧑‍💻 Author

Built by Dev Elijah – Keeping your system safe from infected USB drives!

---
