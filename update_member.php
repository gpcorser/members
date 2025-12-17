<?php
session_start();
require __DIR__ . '/../database/database.php';
require __DIR__ . '/includes/mailer.php';


function ensure_mem_persons_table(PDO $pdo): void {
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

function new_salt_hex(): string {
    return bin2hex(random_bytes(16));
}

function hash_password_pbkdf2(string $password, string $saltHex): string {
    $iterations = 100000;
    $lengthBytes = 32;
    return hash_pbkdf2('sha256', $password, $saltHex, $iterations, $lengthBytes * 2, false);
}

function make_token_raw(): string {
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function site_base_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
    return $scheme . '://' . $host . $dir;
}

function send_verification_email_smtp(string $toEmail, string $verifyUrl): bool {
    $subject = 'Verify your email for Members';
    $body = "Please verify your email by clicking this link:\n\n" . $verifyUrl . "\n\nIf you did not request this, you can ignore this email.";
    $headers = "From: no-reply@" . ($_SERVER['HTTP_HOST'] ?? 'localhost') . "\r\n" .
               "Reply-To: no-reply@" . ($_SERVER['HTTP_HOST'] ?? 'localhost') . "\r\n" .
               "Content-Type: text/plain; charset=UTF-8\r\n";
    return @mail($toEmail, $subject, $body, $headers);
}

function require_login(): int {
    if (empty($_SESSION['mem_user_id'])) {
        header('Location: login.php');
        exit;
    }
    return (int)$_SESSION['mem_user_id'];
}

$pdo = Database::connect();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ensure_mem_persons_table($pdo);

$userId = require_login();

if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    session_destroy();
    header('Location: login.php');
    exit;
}

// Load current user
$stmt = $pdo->prepare("SELECT * FROM mem_persons WHERE id = :id LIMIT 1");
$stmt->execute([':id' => $userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

$message = '';
$errors = [];
$devLink = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'save';

    if ($action === 'resend_verify') {
        if ((int)$user['is_verified'] === 1) {
            $message = 'You are already verified.';
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
                ':id' => $userId
            ]);

            $verifyUrl = site_base_url() . '/verify.php?email=' . urlencode($user['email']) . '&token=' . urlencode($tokenRaw);
            $sent = send_verification_email_smtp($user['email'], $verifyUrl);

            if ($sent) {
                $message = 'Verification email resent.';
            } else {
                $message = 'Email send failed on this server. Use the verification link below (dev mode).';
                $devLink = $verifyUrl;
            }
        }
    }

    if ($action === 'save') {
        $newEmail  = normalize_email_smtp($_POST['email'] ?? $user['email']);
        $fname     = trim((string)($_POST['fname'] ?? ''));
        $lname     = trim((string)($_POST['lname'] ?? ''));
        $address1  = trim((string)($_POST['address1'] ?? ''));
        $address2  = trim((string)($_POST['address2'] ?? ''));
        $city      = trim((string)($_POST['city'] ?? ''));
        $state     = trim((string)($_POST['state'] ?? ''));
        $postal    = trim((string)($_POST['postal'] ?? ''));
        $mobile    = trim((string)($_POST['mobile'] ?? ''));

        if ($newEmail === '' || !filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'A valid email address is required.';
        }

        $currentPw = (string)($_POST['current_password'] ?? '');
        $newPw1    = (string)($_POST['new_password'] ?? '');
        $newPw2    = (string)($_POST['new_password2'] ?? '');
        $changingPassword = ($currentPw !== '' || $newPw1 !== '' || $newPw2 !== '');

        if ($changingPassword) {
            if ($currentPw === '' || $newPw1 === '' || $newPw2 === '') {
                $errors[] = 'To change your password, fill in current password and both new password fields.';
            } else {
                $calcHash = hash_password_pbkdf2($currentPw, $user['salt']);
                if (!hash_equals($user['passwordHash'], $calcHash)) $errors[] = 'Current password is incorrect.';
                if ($newPw1 !== $newPw2) $errors[] = 'New passwords do not match.';
                if (strlen($newPw1) < 8) $errors[] = 'New password must be at least 8 characters long.';
            }
        }

        // Email uniqueness if changed
        if ($newEmail !== $user['email']) {
            $stmt = $pdo->prepare("SELECT id FROM mem_persons WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $newEmail]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($existing && (int)$existing['id'] !== (int)$user['id']) {
                $errors[] = 'That email address is already in use.';
            }
        }

        if (!$errors) {
            try {
                $pdo->beginTransaction();

                $emailChanged = ($newEmail !== $user['email']);
                $willReverify = $emailChanged; // recommended behavior

                $params = [
                    ':id' => $userId,
                    ':email' => $newEmail,
                    ':fname' => ($fname === '' ? null : $fname),
                    ':lname' => ($lname === '' ? null : $lname),
                    ':address1' => ($address1 === '' ? null : $address1),
                    ':address2' => ($address2 === '' ? null : $address2),
                    ':city' => ($city === '' ? null : $city),
                    ':state' => ($state === '' ? null : $state),
                    ':postal' => ($postal === '' ? null : $postal),
                    ':mobile' => ($mobile === '' ? null : $mobile),
                ];

                $tokenRaw = '';
                if ($willReverify) {
                    $tokenRaw = make_token_raw();
                    $params[':is_verified'] = 0;
                    $params[':vtoken'] = hash('sha256', $tokenRaw);
                    $params[':expires'] = (new DateTime('now'))->modify('+24 hours')->format('Y-m-d H:i:s');
                }

                if ($changingPassword) {
                    $newSalt = new_salt_hex();
                    $newHash = hash_password_pbkdf2($newPw1, $newSalt);
                    $params[':salt'] = $newSalt;
                    $params[':passwordHash'] = $newHash;
                }

                $sql = "
                  UPDATE mem_persons
                     SET email = :email,
                         fname = :fname,
                         lname = :lname,
                         address1 = :address1,
                         address2 = :address2,
                         city = :city,
                         state = :state,
                         postal = :postal,
                         mobile = :mobile
                ";

                if ($changingPassword) {
                    $sql .= ", salt = :salt, passwordHash = :passwordHash";
                }

                if ($willReverify) {
                    $sql .= ", is_verified = :is_verified, verification_token = :vtoken, token_expires = :expires";
                }

                $sql .= " WHERE id = :id LIMIT 1";

                $stmt = $pdo->prepare($sql);
                $stmt->execute($params);

                $pdo->commit();

                // refresh session email
                $_SESSION['mem_user_email'] = $newEmail;

                // reload user
                $stmt = $pdo->prepare("SELECT * FROM mem_persons WHERE id = :id LIMIT 1");
                $stmt->execute([':id' => $userId]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                $message = 'Saved. Profile updated.';

                if ($willReverify) {
                    $verifyUrl = site_base_url() . '/verify.php?email=' . urlencode($newEmail) . '&token=' . urlencode($tokenRaw);
                    $sent = send_verification_email_smtp($newEmail, $verifyUrl);
                    if ($sent) {
                        $message .= ' Email changed: verification email sent.';
                    } else {
                        $message .= ' Email changed: email send failed; use dev verification link below.';
                        $devLink = $verifyUrl;
                    }
                } elseif ($changingPassword) {
                    $message .= ' Password changed.';
                }

            } catch (Exception $e) {
                if ($pdo->inTransaction()) $pdo->rollBack();
                $errors[] = 'Update failed: ' . $e->getMessage();
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
  <title>Members - Update Member</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container" style="max-width: 900px;">
  <div class="py-4 d-flex align-items-center justify-content-between">
    <div>
      <h1 class="h4 mb-1">Update Member</h1>
      <div class="text-muted small">Logged in as: <?php echo htmlspecialchars($user['email']); ?></div>
      <div class="text-muted small">Verified: <?php echo ((int)$user['is_verified'] === 1) ? 'Yes' : 'No'; ?></div>
    </div>
    <div class="d-flex gap-2">
      <a class="btn btn-outline-secondary btn-sm" href="?logout=1">Log out</a>
    </div>
  </div>

  <?php if ($message): ?>
    <div class="alert alert-success"><?php echo htmlspecialchars($message); ?></div>
  <?php endif; ?>

  <?php if ($devLink): ?>
    <div class="alert alert-warning">
      Dev verification link: <a href="<?php echo htmlspecialchars($devLink); ?>"><?php echo htmlspecialchars($devLink); ?></a>
    </div>
  <?php endif; ?>

  <?php if ((int)$user['is_verified'] !== 1): ?>
    <div class="alert alert-warning d-flex align-items-center justify-content-between">
      <div>Your email is not verified yet. You must verify before you can log in again after logging out.</div>
      <form method="post" class="m-0">
        <button class="btn btn-outline-dark btn-sm" type="submit" name="action" value="resend_verify">Resend verification</button>
      </form>
    </div>
  <?php endif; ?>

  <?php if ($errors): ?>
    <div class="alert alert-danger">
      <ul class="mb-0">
        <?php foreach ($errors as $err): ?>
          <li><?php echo htmlspecialchars($err); ?></li>
        <?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <form method="post" class="card shadow-sm">
    <div class="card-body p-4">
      <input type="hidden" name="action" value="save">

      <h2 class="h5 mb-3">Contact and Personal Info</h2>
      <div class="row g-3">
        <div class="col-md-6">
          <label class="form-label" for="email">Email (username)</label>
          <input class="form-control" type="email" id="email" name="email" required
                 value="<?php echo htmlspecialchars($user['email'] ?? ''); ?>">
          <div class="form-text">If you change your email, you will be required to verify the new address.</div>
        </div>
        <div class="col-md-3">
          <label class="form-label" for="fname">First name</label>
          <input class="form-control" type="text" id="fname" name="fname"
                 value="<?php echo htmlspecialchars($user['fname'] ?? ''); ?>">
        </div>
        <div class="col-md-3">
          <label class="form-label" for="lname">Last name</label>
          <input class="form-control" type="text" id="lname" name="lname"
                 value="<?php echo htmlspecialchars($user['lname'] ?? ''); ?>">
        </div>

        <div class="col-md-6">
          <label class="form-label" for="address1">Address 1</label>
          <input class="form-control" type="text" id="address1" name="address1"
                 value="<?php echo htmlspecialchars($user['address1'] ?? ''); ?>">
        </div>
        <div class="col-md-6">
          <label class="form-label" for="address2">Address 2</label>
          <input class="form-control" type="text" id="address2" name="address2"
                 value="<?php echo htmlspecialchars($user['address2'] ?? ''); ?>">
        </div>

        <div class="col-md-4">
          <label class="form-label" for="city">City</label>
          <input class="form-control" type="text" id="city" name="city"
                 value="<?php echo htmlspecialchars($user['city'] ?? ''); ?>">
        </div>
        <div class="col-md-4">
          <label class="form-label" for="state">State</label>
          <input class="form-control" type="text" id="state" name="state"
                 value="<?php echo htmlspecialchars($user['state'] ?? ''); ?>">
        </div>
        <div class="col-md-4">
          <label class="form-label" for="postal">Postal</label>
          <input class="form-control" type="text" id="postal" name="postal"
                 value="<?php echo htmlspecialchars($user['postal'] ?? ''); ?>">
        </div>

        <div class="col-md-4">
          <label class="form-label" for="mobile">Mobile</label>
          <input class="form-control" type="text" id="mobile" name="mobile"
                 value="<?php echo htmlspecialchars($user['mobile'] ?? ''); ?>">
        </div>
      </div>

      <hr class="my-4">

      <h2 class="h5 mb-3">Change Password (optional)</h2>
      <div class="row g-3">
        <div class="col-md-4">
          <label class="form-label" for="current_password">Current password</label>
          <input class="form-control" type="password" id="current_password" name="current_password">
        </div>
        <div class="col-md-4">
          <label class="form-label" for="new_password">New password</label>
          <input class="form-control" type="password" id="new_password" name="new_password">
        </div>
        <div class="col-md-4">
          <label class="form-label" for="new_password2">New password (again)</label>
          <input class="form-control" type="password" id="new_password2" name="new_password2">
        </div>
      </div>

      <div class="d-flex gap-2 mt-4">
        <button class="btn btn-primary" type="submit">Save Changes</button>
        <a class="btn btn-outline-secondary" href="update_member.php">Reset</a>
      </div>
    </div>
  </form>
</div>
</body>
</html>
