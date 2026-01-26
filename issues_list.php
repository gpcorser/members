<?php
// members/issues_list.php
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

function ensure_mem_issues_table(PDO $pdo): void {
    $sql = "
    CREATE TABLE IF NOT EXISTS mem_issues (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        person_id INT UNSIGNED NOT NULL,
        subject VARCHAR(200) NOT NULL,
        body TEXT NOT NULL,
        status ENUM('open','closed','onhold') NOT NULL DEFAULT 'open',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_mem_issues_person_id (person_id),
        KEY idx_mem_issues_status (status),
        KEY idx_mem_issues_created_at (created_at),
        CONSTRAINT fk_mem_issues_person
            FOREIGN KEY (person_id) REFERENCES mem_persons(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ";
    $pdo->exec($sql);
}

function ensure_mem_comments_table(PDO $pdo): void {
    // Created now for later use (nested/accordion comments).
    $sql = "
    CREATE TABLE IF NOT EXISTS mem_comments (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        issue_id INT UNSIGNED NOT NULL,
        parent_comment_id INT UNSIGNED DEFAULT NULL,
        person_id INT UNSIGNED NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_mem_comments_issue_id (issue_id),
        KEY idx_mem_comments_parent (parent_comment_id),
        KEY idx_mem_comments_person_id (person_id),
        CONSTRAINT fk_mem_comments_issue
            FOREIGN KEY (issue_id) REFERENCES mem_issues(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_mem_comments_parent
            FOREIGN KEY (parent_comment_id) REFERENCES mem_comments(id)
            ON DELETE CASCADE,
        CONSTRAINT fk_mem_comments_person
            FOREIGN KEY (person_id) REFERENCES mem_persons(id)
            ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    ";
    $pdo->exec($sql);
}

ensure_mem_issues_table($pdo);
ensure_mem_comments_table($pdo);

// ------------------------- HELPERS -------------------------
function h(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function norm_status(string $s): string {
    $s = strtolower(trim($s));
    return in_array($s, ['open','closed','onhold'], true) ? $s : 'open';
}

function get_csrf(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf_token'];
}
function require_csrf(): void {
    $posted = $_POST['csrf_token'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $posted)) {
        http_response_code(400);
        exit('CSRF check failed.');
    }
}

$message = '';
$error = '';

// ------------------------- ACTIONS (POST) -------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'logout') {
        session_destroy();
        header('Location: login.php');
        exit;
    }

    require_csrf();

    if ($action === 'create_issue') {
        $subject = trim((string)($_POST['subject'] ?? ''));
        $body    = trim((string)($_POST['body'] ?? ''));
        $status  = norm_status((string)($_POST['status'] ?? 'open'));

        if ($subject === '' || $body === '') {
            $error = 'Subject and description are required.';
        } else {
            $ins = $pdo->prepare("
                INSERT INTO mem_issues (person_id, subject, body, status)
                VALUES (:pid, :subj, :body, :status)
            ");
            $ins->execute([
                ':pid' => $loggedInUserId,
                ':subj' => $subject,
                ':body' => $body,
                ':status' => $status
            ]);
            header('Location: issues_list.php?msg=created');
            exit;
        }
    }

    if ($action === 'update_issue') {
        $issueId = (int)($_POST['issue_id'] ?? 0);
        $subject = trim((string)($_POST['subject'] ?? ''));
        $body    = trim((string)($_POST['body'] ?? ''));
        $status  = norm_status((string)($_POST['status'] ?? 'open'));

        if ($issueId <= 0) {
            $error = 'Invalid issue id.';
        } elseif ($subject === '' || $body === '') {
            $error = 'Subject and description are required.';
        } else {
            // Only owner can update (for now)
            $chk = $pdo->prepare("SELECT person_id FROM mem_issues WHERE id = :id LIMIT 1");
            $chk->execute([':id' => $issueId]);
            $ownerId = (int)($chk->fetchColumn() ?: 0);

            if ($ownerId !== $loggedInUserId) {
                $error = 'You can only edit your own issues.';
            } else {
                $upd = $pdo->prepare("
                    UPDATE mem_issues
                       SET subject = :subj,
                           body = :body,
                           status = :status
                     WHERE id = :id
                     LIMIT 1
                ");
                $upd->execute([
                    ':subj' => $subject,
                    ':body' => $body,
                    ':status' => $status,
                    ':id' => $issueId
                ]);
                header('Location: issues_list.php?msg=updated');
                exit;
            }
        }
    }

    if ($action === 'delete_issue') {
        $issueId = (int)($_POST['issue_id'] ?? 0);
        if ($issueId <= 0) {
            $error = 'Invalid issue id.';
        } else {
            // Only owner can delete (for now)
            $chk = $pdo->prepare("SELECT person_id FROM mem_issues WHERE id = :id LIMIT 1");
            $chk->execute([':id' => $issueId]);
            $ownerId = (int)($chk->fetchColumn() ?: 0);

            if ($ownerId !== $loggedInUserId) {
                $error = 'You can only delete your own issues.';
            } else {
                $del = $pdo->prepare("DELETE FROM mem_issues WHERE id = :id LIMIT 1");
                $del->execute([':id' => $issueId]);
                header('Location: issues_list.php?msg=deleted');
                exit;
            }
        }
    }
}

// GET message
if (!empty($_GET['msg'])) {
    $map = [
        'created' => 'Issue created.',
        'updated' => 'Issue updated.',
        'deleted' => 'Issue deleted.',
    ];
    $message = $map[$_GET['msg']] ?? '';
}

// ------------------------- FILTERS / SORT -------------------------
$q = trim((string)($_GET['q'] ?? ''));
$statusFilter = trim((string)($_GET['status'] ?? '')); // open/closed/onhold or ''
$posterId = (int)($_GET['poster'] ?? 0);

$sort = (string)($_GET['sort'] ?? 'newest');
$sortSql = "i.created_at DESC";
switch ($sort) {
    case 'oldest':  $sortSql = "i.created_at ASC"; break;
    case 'subject_az': $sortSql = "i.subject ASC"; break;
    case 'subject_za': $sortSql = "i.subject DESC"; break;
    case 'poster_az':  $sortSql = "p.lname ASC, p.fname ASC, p.email ASC"; break;
    case 'poster_za':  $sortSql = "p.lname DESC, p.fname DESC, p.email DESC"; break;
    case 'status':     $sortSql = "i.status ASC, i.created_at DESC"; break;
    default:           $sortSql = "i.created_at DESC"; break;
}

// Build WHERE
$where = [];
$params = [];

if ($statusFilter !== '' && in_array($statusFilter, ['open','closed','onhold'], true)) {
    $where[] = "i.status = :status";
    $params[':status'] = $statusFilter;
}
if ($posterId > 0) {
    $where[] = "i.person_id = :poster";
    $params[':poster'] = $posterId;
}
if ($q !== '') {
    $where[] = "(
        i.subject LIKE :q
        OR i.body LIKE :q
        OR p.email LIKE :q
        OR p.fname LIKE :q
        OR p.lname LIKE :q
    )";
    $params[':q'] = '%' . $q . '%';
}

$whereSql = $where ? ("WHERE " . implode(" AND ", $where)) : "";

// Poster dropdown list
$posterStmt = $pdo->query("
    SELECT id, email, fname, lname
    FROM mem_persons
    ORDER BY lname, fname, email
");
$posters = $posterStmt->fetchAll(PDO::FETCH_ASSOC);

// Pull issues
$listSql = "
    SELECT
        i.id,
        i.person_id,
        i.subject,
        i.body,
        i.status,
        i.created_at,
        i.updated_at,
        p.email,
        p.fname,
        p.lname
    FROM mem_issues i
    JOIN mem_persons p ON p.id = i.person_id
    $whereSql
    ORDER BY $sortSql
    LIMIT 200
";
$listStmt = $pdo->prepare($listSql);
$listStmt->execute($params);
$issues = $listStmt->fetchAll(PDO::FETCH_ASSOC);

// current user display
$meStmt = $pdo->prepare("SELECT email, fname, lname FROM mem_persons WHERE id = :id LIMIT 1");
$meStmt->execute([':id' => $loggedInUserId]);
$me = $meStmt->fetch(PDO::FETCH_ASSOC) ?: ['email' => '(unknown)', 'fname' => '', 'lname' => ''];

Database::disconnect();

$csrf = get_csrf();
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Members - Issues List</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="issues_list.php">Members</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMembers" aria-controls="navMembers" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navMembers">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="update_member.php">MyProfile</a></li>
        <li class="nav-item"><a class="nav-link" href="persons_list.php">Members</a></li>
        <li class="nav-item"><a class="nav-link active" aria-current="page" href="issues_list.php">Issues List</a></li>
      </ul>

      <div class="d-flex align-items-center gap-2">
        <button class="btn btn-success btn-sm" type="button" data-bs-toggle="modal" data-bs-target="#addIssueModal">
          Add Issue
        </button>

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

  <?php if ($message): ?>
    <div class="alert alert-success"><?php echo h($message); ?></div>
  <?php endif; ?>

  <?php if ($error): ?>
    <div class="alert alert-danger"><?php echo h($error); ?></div>
  <?php endif; ?>

  <!-- Filters -->
  <div class="card shadow-sm mb-3">
    <div class="card-body py-2">

      <h2 class="h6 mb-2">Filter / Sort</h2>


      <form method="get" class="row g-2 align-items-center">
  <div class="col-lg-4">
    <input class="form-control form-control-sm" type="text" id="q" name="q"
           value="<?php echo h($q); ?>"
           placeholder="Keyword (subject/body/name/email)">
  </div>

  <div class="col-lg-2">
    <select class="form-select form-select-sm" id="statusFilter" name="status" title="Status">
      <option value="" <?php echo ($statusFilter === '') ? 'selected' : ''; ?>>(any status)</option>
      <option value="open"   <?php echo ($statusFilter === 'open') ? 'selected' : ''; ?>>open</option>
      <option value="onhold" <?php echo ($statusFilter === 'onhold') ? 'selected' : ''; ?>>onhold</option>
      <option value="closed" <?php echo ($statusFilter === 'closed') ? 'selected' : ''; ?>>closed</option>
    </select>
  </div>

  <div class="col-lg-3">
    <select class="form-select form-select-sm" id="poster" name="poster" title="Poster">
      <option value="0">(any poster)</option>
      <?php foreach ($posters as $p): ?>
        <?php
          $pid = (int)$p['id'];
          $label = trim(($p['lname'] ?? '') . ', ' . ($p['fname'] ?? ''));
          if ($label === ',' || $label === '') { $label = $p['email']; }
          else { $label .= " (" . $p['email'] . ")"; }
        ?>
        <option value="<?php echo $pid; ?>" <?php echo ($posterId === $pid) ? 'selected' : ''; ?>>
          <?php echo h($label); ?>
        </option>
      <?php endforeach; ?>
    </select>
  </div>

  <div class="col-lg-2">
    <select class="form-select form-select-sm" id="sort" name="sort" title="Sort">
      <option value="newest"     <?php echo ($sort === 'newest') ? 'selected' : ''; ?>>Newest</option>
      <option value="oldest"     <?php echo ($sort === 'oldest') ? 'selected' : ''; ?>>Oldest</option>
      <option value="subject_az" <?php echo ($sort === 'subject_az') ? 'selected' : ''; ?>>Subject A→Z</option>
      <option value="subject_za" <?php echo ($sort === 'subject_za') ? 'selected' : ''; ?>>Subject Z→A</option>
      <option value="poster_az"  <?php echo ($sort === 'poster_az') ? 'selected' : ''; ?>>Poster A→Z</option>
      <option value="poster_za"  <?php echo ($sort === 'poster_za') ? 'selected' : ''; ?>>Poster Z→A</option>
      <option value="status"     <?php echo ($sort === 'status') ? 'selected' : ''; ?>>Status</option>
    </select>
  </div>

  <div class="col-lg-1 d-flex gap-2 justify-content-end">
    <button class="btn btn-primary btn-sm" type="submit">Go</button>
    <a class="btn btn-outline-secondary btn-sm" href="issues_list.php">Reset</a>
  </div>
</form>

    </div>
  </div>

  <!-- List -->
  <div class="card shadow-sm">
    <div class="card-body py-2">

      <h2 class="h5 mb-3">Issues</h2>

      <?php if (!$issues): ?>
        <div class="alert alert-secondary mb-0">No issues found.</div>
      <?php else: ?>
        <div class="table-responsive">
          <table class="table table-sm align-middle">
            <thead>
              <tr>
                <th style="width: 8%;">ID</th>
                <th style="width: 12%;">Status</th>
                <th style="width: 40%;">Subject</th>
                <th style="width: 18%;">Poster</th>
                <th style="width: 18%;">Date</th>
                <th style="width: 4%;">Actions</th>
              </tr>
            </thead>
            <tbody>
            <?php foreach ($issues as $i): ?>
              <?php
                $isOwner = ((int)$i['person_id'] === $loggedInUserId);
                $posterName = trim(($i['fname'] ?? '') . ' ' . ($i['lname'] ?? ''));
                if ($posterName === '') $posterName = $i['email'];

                $statusBadge = 'secondary';
                if ($i['status'] === 'open') $statusBadge = 'success';
                if ($i['status'] === 'onhold') $statusBadge = 'warning';
                if ($i['status'] === 'closed') $statusBadge = 'dark';
              ?>
              <tr>
                <td><?php echo (int)$i['id']; ?></td>
                <td><span class="badge text-bg-<?php echo h($statusBadge); ?>"><?php echo h($i['status']); ?></span></td>
                <td>
                  <div class="fw-semibold"><?php echo h($i['subject']); ?></div>
                  <div class="text-muted small"><?php echo h(mb_strimwidth($i['body'], 0, 160, '…')); ?></div>
                </td>
                <td><?php echo h($posterName); ?></td>
                <td class="small">
                  <div><?php echo h($i['created_at']); ?></div>
                  <?php if ($i['updated_at'] !== $i['created_at']): ?>
                    <div class="text-muted">upd: <?php echo h($i['updated_at']); ?></div>
                  <?php endif; ?>
                </td>
                <td class="text-nowrap">
                  <?php if ($isOwner): ?>
                    <button
                      class="btn btn-outline-primary btn-sm"
                      type="button"
                      data-bs-toggle="modal"
                      data-bs-target="#editIssueModal"
                      data-issue-id="<?php echo (int)$i['id']; ?>"
                      data-subject="<?php echo h($i['subject']); ?>"
                      data-status="<?php echo h($i['status']); ?>"
                      data-body="<?php echo h($i['body']); ?>"
                    >Edit</button>

                    <form method="post" class="d-inline" onsubmit="return confirm('Delete this issue?');">
                      <input type="hidden" name="csrf_token" value="<?php echo h($csrf); ?>">
                      <input type="hidden" name="issue_id" value="<?php echo (int)$i['id']; ?>">
                      <button class="btn btn-outline-danger btn-sm" type="submit" name="action" value="delete_issue">Del</button>
                    </form>
                  <?php else: ?>
                    <span class="text-muted small">—</span>
                  <?php endif; ?>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>

        <div class="small text-muted">
          Showing up to 200 results. (We can add pagination next.)
        </div>
      <?php endif; ?>

    </div>
  </div>
</div>

<!-- ===================== ADD ISSUE MODAL ===================== -->
<div class="modal fade" id="addIssueModal" tabindex="-1" aria-labelledby="addIssueLabel" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <form method="post" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?php echo h($csrf); ?>">
        <input type="hidden" name="action" value="create_issue">

<div class="modal-header">
  <h5 class="modal-title" id="addIssueLabel">Add Issue</h5>

  <div class="ms-auto d-flex gap-2 align-items-center">
    <button type="submit" class="btn btn-success btn-sm">Post Issue</button>
    <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">Cancel</button>
    <button type="button" class="btn-close ms-1" data-bs-dismiss="modal" aria-label="Close"></button>
  </div>
</div>


        <div class="modal-body">
          <div class="mb-3">
            <label class="form-label" for="add_subject">Subject</label>
            <input class="form-control" type="text" id="add_subject" name="subject" maxlength="200" required>
          </div>

          <div class="mb-3">
            <label class="form-label" for="add_status">Status</label>
            <select class="form-select" id="add_status" name="status">
              <option value="open" selected>open</option>
              <option value="onhold">onhold</option>
              <option value="closed">closed</option>
            </select>
          </div>

          <div class="mb-3">
            <label class="form-label" for="add_body">Description</label>
            <textarea class="form-control" id="add_body" name="body" rows="8" required></textarea>
          </div>
        </div>


      </form>
    </div>
  </div>
</div>

<!-- ===================== EDIT ISSUE MODAL ===================== -->
<div class="modal fade" id="editIssueModal" tabindex="-1" aria-labelledby="editIssueLabel" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <form method="post" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?php echo h($csrf); ?>">
        <input type="hidden" name="action" value="update_issue">
        <input type="hidden" id="edit_issue_id" name="issue_id" value="">

<div class="modal-header">
  <h5 class="modal-title" id="editIssueLabel">Edit Issue</h5>

  <div class="ms-auto d-flex gap-2 align-items-center">
    <button type="submit" class="btn btn-primary btn-sm">Save</button>
    <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">Cancel</button>
    <button type="button" class="btn-close ms-1" data-bs-dismiss="modal" aria-label="Close"></button>
  </div>
</div>


        <div class="modal-body">
          <div class="mb-3">
            <label class="form-label" for="edit_subject">Subject</label>
            <input class="form-control" type="text" id="edit_subject" name="subject" maxlength="200" required>
          </div>

          <div class="mb-3">
            <label class="form-label" for="edit_status">Status</label>
            <select class="form-select" id="edit_status" name="status">
              <option value="open">open</option>
              <option value="onhold">onhold</option>
              <option value="closed">closed</option>
            </select>
          </div>

          <div class="mb-3">
            <label class="form-label" for="edit_body">Description</label>
            <textarea class="form-control" id="edit_body" name="body" rows="8" required></textarea>
          </div>

          <div class="small text-muted">
            You can only edit your own issues.
          </div>
        </div>

      </form>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Populate Edit modal from the "Edit" button data attributes
document.addEventListener('DOMContentLoaded', function () {
  const editModal = document.getElementById('editIssueModal');
  if (!editModal) return;

  editModal.addEventListener('show.bs.modal', function (event) {
    const button = event.relatedTarget;
    if (!button) return;

    const issueId = button.getAttribute('data-issue-id') || '';
    const subject = button.getAttribute('data-subject') || '';
    const status  = button.getAttribute('data-status') || 'open';
    const body    = button.getAttribute('data-body') || '';

    document.getElementById('edit_issue_id').value = issueId;
    document.getElementById('edit_subject').value = subject;
    document.getElementById('edit_status').value  = status;
    document.getElementById('edit_body').value    = body;
  });

  // Optional: clear fields on hide (keeps things neat)
  editModal.addEventListener('hidden.bs.modal', function () {
    document.getElementById('edit_issue_id').value = '';
    document.getElementById('edit_subject').value = '';
    document.getElementById('edit_status').value  = 'open';
    document.getElementById('edit_body').value    = '';
  });
});
</script>
</body>
</html>
