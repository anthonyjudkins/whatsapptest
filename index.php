<?php
     // throwaway webhook logger
     $verifyToken = getenv('WA_VERIFY_TOKEN');
     $appSecret = getenv('WA_APP_SECRET');

     if ($_SERVER['REQUEST_METHOD'] === 'GET') {
          // PHP returns "hub.mode" into "hub_mode"
          if (($_GET['hub_mode'] ?? '') === 'subscribe' && hash_equals($verifyToken, $_GET['hub_verify_token'] ?? '')) {
               echo $_GET['hub_challenge'] ?? '';
               exit;
          }

          http_response_code(403);
          exit;
     }

     $raw = file_get_contents('php://input');
     $expected = 'sha256=' . hash_hmac('sha256', $raw, $appSecret);

     if (!hash_equals($expected, $_SERVER['HTTP_X_HUB_SIGNATURE_256'] ?? '')) {
          http_response_code(401);
          exit;
     }

     file_put_contents('php://stderr', date('c') . ' ' . $raw . PHP_EOL);
     http_response_code(200);
     exit;
