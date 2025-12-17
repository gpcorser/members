<?php
require __DIR__ . '/../database/database.php';

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

function normalize_email(string $email): string {
    return strtolower(trim($email));
}

$pdo = Database::connect();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
ensure_mem_persons_table($pdo);

$email = normalize_email($_GET['email'] ?? '');
$token = trim((string)($_GET['token'] ?? ''));

$message = '';

if ($email === '' || $token === '') {
    $message = 'Invalid verification link (missing email or token).';
} else {
    $stmt = $pdo->prepare("SELECT id, is_verified, verification_token, token_expires FROM mem_persons WHERE email = :email LIMIT 1");
    $stmt->execute([':email' => $email]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        $message = 'Verification failed (account not found).';
    } elseif ((int)$row['is_verified'] === 1) {
        $message = 'Your email is already verified. You can log in.';
    } else {
        $now = new DateTime('now');
        $expires = $row['token_expires'] ? new DateTime($row['token_expires']) : null;

        if (!$row['verification_token'] || !$expires) {
            $message = 'Verification failed (no active token). Please request a new verification email.';
        } elseif ($now > $expires) {
            $message = 'Verification link has expired. Please request a new verification email.';
        } elseif (!hash_equals($row['verification_token'], hash('sha256', $token))) {
            $message = 'Verification failed (token mismatch).';
        } else {
            // Success: verify and clear token
            $upd = $pdo->prepare("
                UPDATE mem_persons
                   SET is_verified = 1,
                       verification_token = NULL,
                       token_expires = NULL
                 WHERE id = :id
                 LIMIT 1
            ");
            $upd->execute([':id' => (int)$row['id']]);

            Database::disconnect();
            header('Location: login.php?verified=1');
            exit;
        }
    }
}

Database::disconnect();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Members - Verify Email</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container" style="max-width: 760px;">
  <div class="py-5">
    <div class="card shadow-sm">
      <div class="card-body p-4">
        <h1 class="h4 mb-3">Email Verification</h1>
        <div class="alert alert-info mb-3"><?php echo htmlspecialchars($message); ?></div>
        <a class="btn btn-primary" href="login.php">Back to Login</a>
      </div>
    </div>
  </div>
</div>
</body>
</html>
