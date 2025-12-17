<?php
session_start();
require __DIR__ . '/../database/database.php';
require __DIR__ . '/includes/db_migrations.php';

function normalize_email_smtp(string $email): string { return strtolower(trim($email)); }
function hash_password_pbkdf2(string $password, string $saltHex): string {
    return hash_pbkdf2('sha256', $password, $saltHex, 100000, 64, false);
}

$email = normalize_email_smtp($_GET['email'] ?? '');
$token = (string)($_GET['token'] ?? '');

$pdo = Database::connect();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ensure_password_reset_columns($pdo);

$message = '';
$okToReset = false;

if ($email && $token) {
    $stmt = $pdo->prepare("
        SELECT id, reset_token_hash, reset_expires
          FROM mem_persons
         WHERE email = :email
         LIMIT 1
    ");
    $stmt->execute([':email' => $email]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && !empty($row['reset_token_hash']) && !empty($row['reset_expires'])) {
        $now = new DateTime('now');
        $exp = new DateTime($row['reset_expires']);
        $tokenHash = hash('sha256', $token);

        if ($now <= $exp && hash_equals($row['reset_token_hash'], $tokenHash)) {
            $okToReset = true;
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = normalize_email_smtp($_POST['email'] ?? '');
    $token = (string)($_POST['token'] ?? '');
    $pass1 = (string)($_POST['pass1'] ?? '');
    $pass2 = (string)($_POST['pass2'] ?? '');

    if ($pass1 === '' || strlen($pass1) < 8) {
        $message = "Password must be at least 8 characters.";
    } elseif ($pass1 !== $pass2) {
        $message = "Passwords do not match.";
    } else {
        // Re-validate token (same logic)
        $stmt = $pdo->prepare("SELECT id, reset_token_hash, reset_expires FROM mem_persons WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            $message = "Invalid or expired reset link.";
        } else {
            $now = new DateTime('now');
            $exp = new DateTime($row['reset_expires'] ?? '2000-01-01');
            $tokenHash = hash('sha256', $token);

            if (empty($row['reset_token_hash']) || $now > $exp || !hash_equals($row['reset_token_hash'], $tokenHash)) {
                $message = "Invalid or expired reset link.";
            } else {
                $salt = bin2hex(random_bytes(16));
                $hash = hash_password_pbkdf2($pass1, $salt);

                $upd = $pdo->prepare("
                    UPDATE mem_persons
                       SET salt = :salt,
                           passwordHash = :ph,
                           reset_token_hash = NULL,
                           reset_expires = NULL
                     WHERE id = :id
                     LIMIT 1
                ");
                $upd->execute([':salt' => $salt, ':ph' => $hash, ':id' => (int)$row['id']]);

                $message = "Password reset successful. You may now log in.";
                $okToReset = false;
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
  <title>Members - Reset Password</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container" style="max-width: 640px;">
  <div class="py-5">
    <div class="card shadow-sm">
      <div class="card-body p-4">
        <h1 class="h4 mb-3">Reset Password</h1>

        <?php if ($message): ?>
          <div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <?php if ($okToReset): ?>
          <form method="post" autocomplete="off">
            <input type="hidden" name="email" value="<?php echo htmlspecialchars($email); ?>">
            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

            <div class="mb-3">
              <label class="form-label" for="pass1">New Password</label>
              <input class="form-control" type="password" id="pass1" name="pass1" required>
            </div>
            <div class="mb-3">
              <label class="form-label" for="pass2">Confirm New Password</label>
              <input class="form-control" type="password" id="pass2" name="pass2" required>
              <div class="form-text">Minimum 8 characters.</div>
            </div>

            <button class="btn btn-primary" type="submit">Reset Password</button>
            <a class="btn btn-link" href="login.php">Back to Login</a>
          </form>
        <?php else: ?>
          <div class="alert alert-warning">
            This reset link is invalid or expired. Please request a new one.
          </div>
          <a class="btn btn-primary" href="forgot_password.php">Request Reset Link</a>
          <a class="btn btn-link" href="login.php">Back to Login</a>
        <?php endif; ?>

      </div>
    </div>
  </div>
</div>
</body>
</html>
