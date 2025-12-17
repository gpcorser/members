<?php
// members/includes/mailer.php

require_once __DIR__ . '/../../email/email_smtp.php';

require_once __DIR__ . '/../lib/PHPMailer/src/Exception.php';
require_once __DIR__ . '/../lib/PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/../lib/PHPMailer/src/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/**
 * Internal helper: send plain-text email via server-local sendmail.
 */
function send_mail_plain(string $toEmail, string $subject, string $body): bool
{
    if (empty($toEmail) || empty($subject) || empty($body)) {
        error_log("MAILER: missing parameters");
        return false;
    }

    $mail = new PHPMailer(true);

    try {
        // Use GoDaddy local mail transport
        $mail->isSendmail();

        $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME ?? 'Members App');
        $mail->addAddress($toEmail);

        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body    = $body;

        $mail->send();
        return true;

    } catch (Exception $e) {
        error_log("MAILER error: " . $mail->ErrorInfo);
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
