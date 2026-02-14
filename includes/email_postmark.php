<?php
require_once __DIR__ . '../../database/email_config.php';

function send_email_postmark(string $to, string $subject, string $htmlBody): bool
{
    $payload = [
        'From' => EMAIL_FROM_NAME . ' <' . EMAIL_FROM . '>',
        'To' => $to,
        'Subject' => $subject,
        'HtmlBody' => $htmlBody,
        'TextBody' => strip_tags($htmlBody),
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

    if ($resp === false) { error_log("Postmark curl error: $err"); return false; }
    if ($http < 200 || $http >= 300) { error_log("Postmark HTTP $http response: $resp"); return false; }

    return true;
}
