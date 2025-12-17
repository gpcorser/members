<?php
// -----------------------------------------------------------------------------
// members/includes/mailer.php
// Purpose: Send verification emails for the "members" app.
//
// This version uses the server's local mail transport (sendmail) instead of
// outbound SMTP. This avoids GoDaddy shared-hosting outbound SMTP restrictions.
// -----------------------------------------------------------------------------

require_once __DIR__ . '/../../email/email_smtp.php'; // for MAIL_FROM / MAIL_FROM_NAME (no SMTP needed)

require_once __DIR__ . '/../lib/PHPMailer/src/Exception.php';
require_once __DIR__ . '/../lib/PHPMailer/src/PHPMailer.php';
require_once __DIR__ . '/../lib/PHPMailer/src/SMTP.php'; // ok to keep (PHPMailer references it internally)

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if (!function_exists('send_verification_email_smtp')) {

    /**
     * Send a verification email.
     * Note: name kept as send_verification_email_smtp() so you do not have to
     * change callers elsewhere in your app, even though we are not using SMTP.
     */
    function send_verification_email_smtp(string $toEmail, string $verifyUrl): bool
    {
        // Basic sanity checks
        if (empty($toEmail) || empty($verifyUrl)) {
            error_log("MAILER: missing toEmail or verifyUrl");
            return false;
        }
        if (empty(MAIL_FROM)) {
            error_log("MAILER: MAIL_FROM not set (check email/email_smtp.php)");
            return false;
        }

        error_log("MAILER: entered send_verification_email_smtp() (sendmail mode)");
        error_log("MAILER: from=" . MAIL_FROM . " to=" . $toEmail);

        $mail = new PHPMailer(true);

        try {
            // Use server-local sendmail/postfix transport (no outbound SMTP)
            $mail->isSendmail();

            // Optional: if sendmail path is non-standard, uncomment and set:
            // $mail->Sendmail = '/usr/sbin/sendmail';

            // Headers / recipients
            $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME ?? 'Members App');
            $mail->addAddress($toEmail);

            // Content
            $mail->isHTML(false);
            $mail->Subject = 'Verify your email for Members';
            $mail->Body =
                "Please verify your email by clicking this link:\n\n" .
                $verifyUrl . "\n\n" .
                "If you did not request this, you can ignore this email.";

            $mail->send();
            error_log("MAILER: sendmail accepted message");
            return true;

        } catch (Exception $e) {
            // Do not expose details to browser; log server-side only
            error_log("MAILER: sendmail exception=" . $e->getMessage());
            error_log("MAILER: ErrorInfo=" . $mail->ErrorInfo);
            return false;
        }
    }
}
