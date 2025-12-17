<?php
function ensure_password_reset_columns(PDO $pdo): void {
    // reset_token_hash
    try {
        $pdo->exec("ALTER TABLE mem_persons ADD COLUMN reset_token_hash VARCHAR(64) DEFAULT NULL");
    } catch (PDOException $e) { /* ignore: already exists */ }

    // reset_expires
    try {
        $pdo->exec("ALTER TABLE mem_persons ADD COLUMN reset_expires DATETIME DEFAULT NULL");
    } catch (PDOException $e) { /* ignore: already exists */ }
}
