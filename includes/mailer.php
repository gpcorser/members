<?php
// members/includes/mailer.php

/**
 * Transactional email sender for the Members App.
 *
 * Primary transport: Postmark HTTP API (reliable on shared hosting).
 * Optional fallback: PHPMailer via PHP mail() for local/dev only.
 *
 * Requirements:
 *   - Create members/includes/email_config.php (NOT committed) containing:
 *       define('EMAIL_FROM', 'no-reply@georgecorser.com');
 *       define('EMAIL_FROM_NAME', 'GeorgeCorser Members App');
 *       define('POSTMARK_SERVER_TOKEN', '...server token...');
 *
 *   - Ensure cURL is enabled on the server (common on GoDaddy).
 */

require_once __DIR__ . '/../../database/email_config.php'; // you create this (gitignored)

function postmark_send_plain(string $toEmail, string $subject, string $body): bool
{
    if (empty($toEmail) || empty($subject) || empty($body)) {
        error_log("MAILER(Postmark): missing parameters");
        return false;
    }

    $payload = [
        'From' => (EMAIL_FROM_NAME ?? 'Members App') . ' <' . EMAIL_FROM . '>',
        'To' => $toEmail,
        'Subject' => $subject,
        'TextBody' => $body,
        'MessageStream' => 'outbound',
    ];

    $ch = curl_init('https://api.postmarkapp.com/email');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Content-Type: application/json',
            'X-Postmark-Server-Token: ' . POSTMARK_SERVER_TOKEN,
        ],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_TIMEOUT => 15,
    ]);

    $resp = curl_exec($ch);
    $http = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($resp === false) {
        error_log("MAILER(Postmark) curl error: $err");
        return false;
    }

    if ($http < 200 || $http >= 300) {
        error_log("MAILER(Postmark) HTTP $http response: $resp");
        return false;
    }

    return true;
}

/**
 * Internal helper: send plain-text email.
 * Uses Postmark first. Optionally falls back to PHPMailer (mail()) for local/dev.
 */
function send_mail_plain(string $toEmail, string $subject, string $body): bool
{
    // 1) Preferred path: Postmark
    $ok = postmark_send_plain($toEmail, $subject, $body);
    if ($ok) return true;

    // 2) Fallback path (optional): PHPMailer via mail() — useful if Postmark config missing locally.
    // If you do NOT want any fallback, delete everything below this line and just "return false".
    if (!defined('MAIL_FALLBACK_ENABLED') || MAIL_FALLBACK_ENABLED !== true) {
        return false;
    }

    // Lazy-load PHPMailer only if fallback enabled
    require_once __DIR__ . '/../lib/PHPMailer/src/Exception.php';
    require_once __DIR__ . '/../lib/PHPMailer/src/PHPMailer.php';
    require_once __DIR__ . '/../lib/PHPMailer/src/SMTP.php';

    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

    try {
        $mail->isMail();
        $mail->setFrom(EMAIL_FROM, EMAIL_FROM_NAME ?? 'Members App');
        $mail->addAddress($toEmail);

        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body    = $body;

        $mail->send();
        return true;

    } catch (\PHPMailer\PHPMailer\Exception $e) {
        error_log("MAILER(Fallback) exception: " . $e->getMessage());
        error_log("MAILER(Fallback) ErrorInfo: " . $mail->ErrorInfo);
        return false;
    }
}

/**
 * Send email verification message.
 */
function send_verification_email(string $toEmail, string $verifyUrl): bool
{
    $subject = 'Verify your email address';

    $body =
        "Welcome!\n\n" .
        "Please verify your email address by clicking the link below:\n\n" .
        $verifyUrl . "\n\n" .
        "This link expires after a limited time.\n\n" .
        "If you did not create an account, you can safely ignore this message.";

    return send_mail_plain($toEmail, $subject, $body);
}

/**
 * Send password reset message.
 */
function send_password_reset_email(string $toEmail, string $resetUrl): bool
{
    $subject = 'Password reset request';

    $body =
        "A password reset was requested for your account.\n\n" .
        "To reset your password, click the link below:\n\n" .
        $resetUrl . "\n\n" .
        "This link will expire shortly.\n\n" .
        "If you did not request a password reset, you can ignore this message.";

    return send_mail_plain($toEmail, $subject, $body);
}
