<?php
// members/persons_list.php
session_start();
require __DIR__ . '/../database/database.php';

// ------------------------- AUTH -------------------------
if (empty($_SESSION['mem_user_id'])) {
    header('Location: login.php');
    exit;
}
$loggedInUserId = (int)$_SESSION['mem_user_id'];

// ------------------------- DB -------------------------
$pdo = Database::connect();
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// ------------------------- HELPERS -------------------------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }

// Safe excerpt helper (some shared-hosting PHP builds may not have mbstring enabled).
function excerpt(string $s, int $max = 80): string {
    $s = (string)$s;
    $ellipsis = '…';
    if (function_exists('mb_strimwidth')) {
        return mb_strimwidth($s, 0, $max, $ellipsis);
    }
    if (strlen($s) <= $max) return $s;
    return substr($s, 0, max(0, $max - 1)) . $ellipsis;
}

function get_csrf(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf_token'];
}
function require_csrf(): void {
    $posted = $_POST['csrf_token'] ?? '';
    if (!$posted || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $posted)) {
        http_response_code(403);
        exit('CSRF validation failed');
    }
}

// ------------------------- ACTIONS -------------------------
$csrf = get_csrf();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'logout') {
        require_csrf();
        session_destroy();
        header('Location: login.php');
        exit;
    }
}

// ------------------------- DATA -------------------------
$meStmt = $pdo->prepare("SELECT email, fname, lname FROM mem_persons WHERE id = :id LIMIT 1");
$meStmt->execute([':id' => $loggedInUserId]);
$me = $meStmt->fetch(PDO::FETCH_ASSOC) ?: ['email' => '(unknown)', 'fname' => '', 'lname' => ''];

$q = trim((string)($_GET['q'] ?? ''));
$params = [];
$where = [];

if ($q !== '') {
    $where[] = "(email LIKE :q OR fname LIKE :q OR lname LIKE :q OR mobile LIKE :q OR city LIKE :q OR state LIKE :q)";
    $params[':q'] = '%' . $q . '%';
}
$whereSql = $where ? ("WHERE " . implode(" AND ", $where)) : "";

// Pull members
$listSql = "
    SELECT *
    FROM mem_persons
    $whereSql
    ORDER BY lname, fname, email
";
$stmt = $pdo->prepare($listSql);
$stmt->execute($params);
$persons = $stmt->fetchAll(PDO::FETCH_ASSOC);

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Members</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="persons_list.php">Members</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMembers" aria-controls="navMembers" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navMembers">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="update_member.php">MyProfile</a></li>
        <li class="nav-item"><a class="nav-link active" aria-current="page" href="persons_list.php">Members</a></li>
        <li class="nav-item"><a class="nav-link" href="issues_list.php">Issues List</a></li>
      </ul>

      <div class="d-flex align-items-center gap-2">
        <div class="text-white small d-none d-lg-block">
          <?php
            $meName = trim(($me['fname'] ?? '') . ' ' . ($me['lname'] ?? ''));
            echo h($meName !== '' ? $meName : ($me['email'] ?? '(unknown)'));
          ?>
        </div>

        <form method="post" class="m-0">
          <input type="hidden" name="csrf_token" value="<?php echo h($csrf); ?>">
          <button class="btn btn-outline-light btn-sm" type="submit" name="action" value="logout">Log out</button>
        </form>
      </div>
    </div>
  </div>
</nav>

<div class="container py-4">
  <div class="d-flex align-items-center justify-content-between flex-wrap gap-2">
    <h1 class="h3 m-0">Members</h1>

    <form class="d-flex gap-2" method="get" action="persons_list.php" role="search">
      <input class="form-control form-control-sm" type="search" name="q" value="<?php echo h($q); ?>" placeholder="Search members...">
      <button class="btn btn-outline-primary btn-sm" type="submit">Search</button>
      <?php if ($q !== ''): ?>
        <a class="btn btn-outline-secondary btn-sm" href="persons_list.php">Clear</a>
      <?php endif; ?>
    </form>
  </div>

  <div class="mt-3 card shadow-sm">
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-striped table-hover align-middle mb-0">
          <thead class="table-light">
            <tr>
              <th style="width: 70px;">ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Mobile</th>
              <th>Location</th>
              <th style="width: 110px;">Verified</th>
            </tr>
          </thead>
          <tbody>
          <?php if (!$persons): ?>
            <tr><td colspan="6" class="text-center py-4 text-muted">No members found.</td></tr>
          <?php else: ?>
            <?php foreach ($persons as $p): ?>
              <?php
                $name = trim((string)($p['fname'] ?? '') . ' ' . (string)($p['lname'] ?? ''));
                $email = (string)($p['email'] ?? '');
                $mobile = (string)($p['mobile'] ?? '');
                $loc = trim((string)($p['city'] ?? '') . ( ($p['state'] ?? '') ? (', ' . (string)$p['state']) : '' ));
                $verified = (int)($p['is_verified'] ?? 0) === 1 ? 'Yes' : 'No';
              ?>
              <tr>
                <td><?php echo (int)($p['id'] ?? 0); ?></td>
                <td><?php echo h($name !== '' ? $name : '(no name)'); ?></td>
                <td><?php echo h(excerpt($email, 60)); ?></td>
                <td><?php echo h(excerpt($mobile, 30)); ?></td>
                <td><?php echo h($loc !== '' ? $loc : ''); ?></td>
                <td><?php echo h($verified); ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <p class="text-muted small mt-3 mb-0">
    Tip: To add a new member account, use the registration form on the login page.
  </p>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
