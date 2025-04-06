A simple web shell and shell


### Features**

#### **1. Security Enhancements**
- **Token-Based Authentication:** Replaced password with a 64-character random token stored in a file, validated via GET/POST.
- **IP Whitelisting:** Restricts access to specified IPs.
- **Rate Limiting:** Prevents brute-force attacks with a lockout mechanism.
- **Encryption:** AES-256-CBC encryption for sensitive data (e.g., file contents if extended).
- **Security Headers:** Protects against common web vulnerabilities.

#### **2. Web Shell Features**
- **Multi-Function Interface:** A dropdown menu offers actions: execute commands, upload files, download files, list directories, read files, write files, and scan ports.
- **Dynamic Form:** File input appears only for upload actions via JavaScript.
- **Stylish UI:** Terminal-like design with a dark theme and green text for a hacker aesthetic.
- **Error Handling:** Try-catch blocks ensure graceful error reporting.
- **Logging:** All actions are logged with timestamps and IP addresses.

#### **3. Command-Line Shell Features**
- **Interactive CLI:** Supports multiple commands with a help menu.
- **Commands:** `exec`, `ls`, `read`, `write`, `scan`, `upload` (local), `download` (local), `exit`.
- **File Operations:** Local file upload/download within the CLI context.
- **Robust Parsing:** Handles multi-word inputs with space separation.
- **Error Handling:** Exceptions are caught and displayed cleanly.

#### **4. Comprehensive Functionality**
- **Command Execution:** Runs any shell command with output display.
- **File Management:** Upload, download, list, read, and write files.
- **Network Tools:** Port scanning for remote hosts.
- **Extensibility:** Can be extended with additional actions (e.g., database queries, user management) by adding cases.

#### **5. Usability**
- **Web Shell:** Intuitive form-based interface with immediate feedback.
- **CLI Shell:** Interactive prompt with clear instructions and help.

---

### **How to Use**

#### **1. Setup**
- Save as `ultimateshell.php` on a PHP-enabled server.
- Set secure paths for `TOKEN_FILE` and `LOG_FILE` (outside web root).
- Update `ENCRYPTION_KEY` to a strong, unique value.
- Add allowed IPs to `$allowedIPs`.

#### **2. Access**
- **Web Access:** Visit `http://yourserver.com/ultimateshell.php`.
  - Enter the token from `TOKEN_FILE`.
  - Choose "Web Shell" or "Command-Line Shell".
- **CLI Access:** Run from terminal:
  ```bash
  php ultimateshell.php
  ```
  - The script auto-detects CLI mode and skips the form.

#### **3. Web Shell Usage**
- Select an action (e.g., "Execute Command").
- Enter parameters (e.g., `whoami` for `exec`, or a file path for `read`).
- For uploads, select a file and specify a target path.
- Submit to see results in a formatted `<pre>` block.

#### **4. CLI Shell Usage**
- Type commands like:
  - `exec whoami` - Runs `whoami`.
  - `ls /path/to/dir` - Lists directory contents.
  - `write /path/to/file "Hello World"` - Writes to a file.
  - `scan google.com 80` - Checks if port 80 is open.
  - `upload source.txt /path/to/dest.txt` - Copies a local file.
  - `download /path/to/source.txt dest.txt` - Saves a file locally.
  - `help` - Shows usage.
  - `exit` - Quits the shell.

---

### **Why This Is the "Best"**
- **Security:** Token-based auth, IP restrictions, rate limiting, and encryption.
- **Functionality:** Covers command execution, file operations, and network scanning.
- **Flexibility:** Works seamlessly in both web and CLI contexts.
- **Usability:** Intuitive UI for web, interactive CLI with help.
- **Robustness:** Comprehensive error handling and logging.

