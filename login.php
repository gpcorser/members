<?php
session_start();
require __DIR__ . '/../database/database.php';
require __DIR__ . '/includes/mailer.php';


function ensure_mem_persons_table(PDO $pdo): void {

    require_once __DIR__ . '/includes/db_migrations.php';
    ensure_password_reset_columns($pdo);


    $sql = "
    CREATE TABLE IF NOT EXISTS mem_persons (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL,
        salt VARCHAR(64) NOT NULL,
        passwordHash VARCHAR(128) NOT NULL,

        is_verified TINYINT(1) NOT NULL DEFAULT 0,
        verification_token VARCHAR(128) DEFAULT NULL,
        token_expires DATETIME DEFAULT NULL,

        fname VARCHAR(80) DEFAULT NULL,
        lname VARCHAR(80) DEFAULT NULL,
        address1 VARCHAR(120) DEFAULT NULL,
        address2 VARCHAR(120) DEFAULT NULL,
        city VARCHAR(80) DEFAULT NULL,
        state VARCHAR(40) DEFAULT NULL,
        postal VARCHAR(20) DEFAULT NULL,
        mobile VARCHAR(30) DEFAULT NULL,

        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

        PRIMARY KEY (id),
        UNIQUE KEY uq_mem_persons_email (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ";
    $pdo->exec($sql);
}

function normalize_email_smtp(string $email): string {
    return strtolower(trim($email));
}

function hash_password_pbkdf2(string $password, string $saltHex): string {
    $iterations = 100000;
    $lengthBytes = 32;
    return hash_pbkdf2('sha256', $password, $saltHex, $iterations, $lengthBytes * 2, false);
}

function make_token_raw(): string {
    // URL-safe token
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function site_base_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
    return $scheme . '://' . $host . $dir;
}

/*
function send_verification_email_smtp(string $toEmail, string $verifyUrl): bool {
    $subject = 'Verify your email for Members';
    $body = "Please verify your email by clicking this link:\n\n" . $verifyUrl . "\n\nIf you did not request this, you can ignore this email.";
    $headers = "From: no-reply@" . ($_SERVER['HTTP_HOST'] ?? 'localhost') . "\r\n" .
               "Reply-To: no-reply@" . ($_SERVER['HTTP_HOST'] ?? 'localhost') . "\r\n" .
               "Content-Type: text/plain; charset=UTF-8\r\n";
    return @mail($toEmail, $subject, $body, $headers);
}
    */

$pdo = Database::connect();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ensure_mem_persons_table($pdo);

if (!empty($_SESSION['mem_user_id'])) {
    header('Location: update_member.php');
    exit;
}

$message = '';
$devLink = '';

// If redirected from verify.php success
if (isset($_GET['verified']) && $_GET['verified'] === '1') {
    $message = 'Email verified. You can now log in.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $email = normalize_email_smtp($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    if ($action === 'join') {
        if ($email === '' || $password === '') {
            $message = 'To join, email and password are required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = 'Please enter a valid email address.';
        } elseif (strlen($password) < 8) {
            $message = 'Password must be at least 8 characters.';
        } else {
            $stmt = $pdo->prepare("SELECT id FROM mem_persons WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            if ($stmt->fetch()) {
                $message = 'That email is already registered. Please log in or resend verification.';
            } else {
                $salt = bin2hex(random_bytes(16));
                $hash = hash_password_pbkdf2($password, $salt);

                $tokenRaw = make_token_raw();
                $tokenHash = hash('sha256', $tokenRaw);
                $expires = (new DateTime('now'))->modify('+24 hours')->format('Y-m-d H:i:s');

                $ins = $pdo->prepare("
                    INSERT INTO mem_persons (email, salt, passwordHash, is_verified, verification_token, token_expires)
                    VALUES (:email, :salt, :hash, 0, :vtoken, :expires)
                ");
                $ins->execute([
                    ':email' => $email,
                    ':salt' => $salt,
                    ':hash' => $hash,
                    ':vtoken' => $tokenHash,
                    ':expires' => $expires
                ]);

                $verifyUrl = site_base_url() . '/verify.php?email=' . urlencode($email) . '&token=' . urlencode($tokenRaw);

                $sent = send_verification_email_smtp($email, $verifyUrl);
                if ($sent) {
                    $message = 'Account created. Verification email sent. Please verify before logging in.';
                } else {
                    // XAMPP/dev fallback: show link so you can complete flow without SMTP
                    $message = 'Account created. Email send failed on this server. Use the verification link below (dev mode).';
                    $devLink = $verifyUrl;
                }
            }
        }
    }

    if ($action === 'login') {
        if ($email === '' || $password === '') {
            $message = 'Email and password are required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = 'Please enter a valid email address.';
        } else {
            $stmt = $pdo->prepare("SELECT * FROM mem_persons WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                $message = 'Login failed. Check your email and password.';
            } else {
                $calcHash = hash_password_pbkdf2($password, $user['salt']);
                if (!hash_equals($user['passwordHash'], $calcHash)) {
                    $message = 'Login failed. Check your email and password.';
                } elseif ((int)$user['is_verified'] !== 1) {
                    $message = 'Login blocked: your email is not verified. Click Resend Verification.';
                } else {
                    session_regenerate_id(true);
                    $_SESSION['mem_user_id'] = (int)$user['id'];
                    $_SESSION['mem_user_email'] = $user['email'];
                    header('Location: update_member.php');
                    exit;
                }
            }
        }
    }

    if ($action === 'resend') {
        if ($email === '') {
            $message = 'Enter your email above, then click Resend Verification.';
        } else {
            $stmt = $pdo->prepare("SELECT id, is_verified FROM mem_persons WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$row) {
                $message = 'Account not found.';
            } elseif ((int)$row['is_verified'] === 1) {
                $message = 'This email is already verified. Please log in.';
            } else {
                $tokenRaw = make_token_raw();
                $tokenHash = hash('sha256', $tokenRaw);
                $expires = (new DateTime('now'))->modify('+24 hours')->format('Y-m-d H:i:s');

                $upd = $pdo->prepare("
                    UPDATE mem_persons
                       SET verification_token = :vtoken,
                           token_expires = :expires
                     WHERE id = :id
                     LIMIT 1
                ");
                $upd->execute([
                    ':vtoken' => $tokenHash,
                    ':expires' => $expires,
                    ':id' => (int)$row['id']
                ]);

                $verifyUrl = site_base_url() . '/verify.php?email=' . urlencode($email) . '&token=' . urlencode($tokenRaw);
                $sent = send_verification_email_smtp($email, $verifyUrl);

                if ($sent) {
                    $message = 'Verification email resent.';
                } else {
                    $message = 'Email send failed on this server. Use the verification link below (dev mode).';
                    $devLink = $verifyUrl;
                }
            }
        }
    }
}

Database::disconnect();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Members - Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container" style="max-width: 640px;">
  <div class="py-5">
    <div class="card shadow-sm">
      <div class="card-body p-4">
        <h1 class="h4 mb-3">Members</h1>

        <?php if ($message): ?>
          <div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <?php if ($devLink): ?>
          <div class="alert alert-warning">
            Dev verification link: <a href="<?php echo htmlspecialchars($devLink); ?>"><?php echo htmlspecialchars($devLink); ?></a>
          </div>
        <?php endif; ?>

        <form method="post" autocomplete="off">
          <div class="mb-3">
            <label class="form-label" for="email">Email (username)</label>
            <input class="form-control" type="email" id="email" name="email"
                   required value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
          </div>
          <div class="mb-3">
            <label class="form-label" for="password">Password</label>
            <input class="form-control" type="password" id="password" name="password">
            <div class="form-text">Minimum 8 characters for Join.</div>
          </div>

          <div class="d-flex flex-wrap gap-2">
            <button class="btn btn-primary" type="submit" name="action" value="login">Log In</button>
            <button class="btn btn-success" type="submit" name="action" value="join">Join</button>
            <button class="btn btn-outline-secondary" type="submit" name="action" value="resend">Resend Verification</button>
            <a class="btn btn-outline-primary" href="forgot_password.php">Forgot Password</a>

          </div>
        </form>

        <hr class="my-4">
        <div class="small text-muted">
          Email verification is required for login. If you are testing on XAMPP and mail() is not configured,
          the app will display a dev verification link after Join/Resend.
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>
