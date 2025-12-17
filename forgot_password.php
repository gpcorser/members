<?php
session_start();
require __DIR__ . '/../database/database.php';
require __DIR__ . '/includes/mailer.php';
require __DIR__ . '/includes/db_migrations.php';

function normalize_email_smtp(string $email): string { return strtolower(trim($email)); }
function make_token_raw(): string { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }
function site_base_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $dir = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/\\');
    return $scheme . '://' . $host . $dir;
}

$pdo = Database::connect();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ensure_password_reset_columns($pdo);

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = normalize_email_smtp($_POST['email'] ?? '');

    // Always respond generically (prevents account enumeration)
    $message = "If that email exists, a password reset link has been sent.";

    if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $stmt = $pdo->prepare("SELECT id FROM mem_persons WHERE email = :email LIMIT 1");
        $stmt->execute([':email' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            $tokenRaw  = make_token_raw();
            $tokenHash = hash('sha256', $tokenRaw);
            $expires   = (new DateTime('now'))->modify('+30 minutes')->format('Y-m-d H:i:s');

            $upd = $pdo->prepare("
                UPDATE mem_persons
                   SET reset_token_hash = :h,
                       reset_expires = :e
                 WHERE id = :id
                 LIMIT 1
            ");
            $upd->execute([':h' => $tokenHash, ':e' => $expires, ':id' => (int)$row['id']]);

            $resetUrl = site_base_url() . "/reset_password.php?email=" . urlencode($email) . "&token=" . urlencode($tokenRaw);
            // Reuse your existing mailer function
            send_password_reset_email($email, $resetUrl);

        }
    }
}

Database::disconnect();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Members - Forgot Password</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container" style="max-width: 640px;">
  <div class="py-5">
    <div class="card shadow-sm">
      <div class="card-body p-4">
        <h1 class="h4 mb-3">Forgot Password</h1>

        <?php if ($message): ?>
          <div class="alert alert-info"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <form method="post" autocomplete="off">
          <div class="mb-3">
            <label class="form-label" for="email">Email</label>
            <input class="form-control" type="email" id="email" name="email" required>
          </div>
          <button class="btn btn-primary" type="submit">Send Reset Link</button>
          <a class="btn btn-link" href="login.php">Back to Login</a>
        </form>

        <hr class="my-4">
        <div class="small text-muted">
          For security, we do not confirm whether an email address is registered.
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>
