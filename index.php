<?php
// index.php - simple UI + Google Vision integration using Service Account JSON and JWT OAuth2 exchange
// Place this file in your XAMPP htdocs (e.g. C:\xampp\htdocs\smartbin\index.php)
// Put your service account JSON in keys/service_account.json relative to this file

// ----- CONFIG -----
$SERVICE_ACCOUNT_FILE = __DIR__ . '/keys/thermal-shuttle-480412-g1-ab7833ab300c.json'; // put your json here
$OAUTH_TOKEN_URI = 'https://oauth2.googleapis.com/token';
$VISION_ENDPOINT = 'https://vision.googleapis.com/v1/images:annotate';

// map some common Vision labels to our 4 categories
$LABEL_MAP = [
    // plastic
    'Plastic bottle' => 'Plastic',
    'Bottle' => 'Plastic',
    'Plastic' => 'Plastic',
    'PET' => 'Plastic',
    'Drink bottle' => 'Plastic',

    // glass
    'Glass bottle' => 'Glass',
    'Glass' => 'Glass',

    // metal
    'Can' => 'Metal',
    'Tin can' => 'Metal',
    'Aluminium' => 'Metal',
    'Metal' => 'Metal',
    'Aluminum' => 'Metal',

    // paper
    'Paper' => 'Paper',
    'Cardboard' => 'Paper',
    'Carton' => 'Paper'
];

// utility: base64url encode
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// create JWT and exchange for access token
function get_access_token_from_service_account($service_account_file) {
    global $OAUTH_TOKEN_URI;

    if (!file_exists($service_account_file)) {
        throw new Exception("Service account file not found: $service_account_file");
    }

    $sa = json_decode(file_get_contents($service_account_file), true);
    if (!$sa) throw new Exception("Invalid service account JSON.");

    $now = time();
    $exp = $now + 3600; // 1 hour
    $header = ['alg' => 'RS256', 'typ' => 'JWT'];
    $scope = 'https://www.googleapis.com/auth/cloud-platform';

    $claim = [
        'iss' => $sa['client_email'],
        'scope' => $scope,
        'aud' => $OAUTH_TOKEN_URI,
        'exp' => $exp,
        'iat' => $now
    ];

    $jwt_header = base64url_encode(json_encode($header));
    $jwt_claim = base64url_encode(json_encode($claim));
    $unsigned_jwt = $jwt_header . "." . $jwt_claim;

    // sign with private_key (PKCS8 PEM) from service account
    $private_key = $sa['private_key'];

    $signature = '';
    $ok = openssl_sign($unsigned_jwt, $signature, $private_key, OPENSSL_ALGO_SHA256);
    if (!$ok) {
        throw new Exception("Failed to sign JWT with private key. Check openssl extension and key format.");
    }
    $signed = $unsigned_jwt . "." . base64url_encode($signature);

    // exchange JWT for access token
    $post_fields = http_build_query([
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $signed
    ]);

    $ch = curl_init($OAUTH_TOKEN_URI);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    $resp = curl_exec($ch);
    if ($resp === false) {
        throw new Exception("cURL error: " . curl_error($ch));
    }
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $resp_json = json_decode($resp, true);
    if ($http_code !== 200 || !isset($resp_json['access_token'])) {
        throw new Exception("Failed to get access token: HTTP $http_code - " . $resp);
    }

    return $resp_json['access_token'];
}


// handle POST (file upload)
$analysis_result = null;
$error_msg = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception("Upload failed or no file uploaded.");
        }

        $tmpname = $_FILES['image']['tmp_name'];
        $img_data = file_get_contents($tmpname);
        $base64 = base64_encode($img_data);

        // get access token
        $access_token = get_access_token_from_service_account($SERVICE_ACCOUNT_FILE);

        // build Vision API request
        $request_body = [
            "requests" => [
                [
                    "image" => ["content" => $base64],
                    "features" => [
                        ["type" => "LABEL_DETECTION", "maxResults" => 10]
                    ]
                ]
            ]
        ];
        $ch = curl_init($VISION_ENDPOINT);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request_body));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            "Authorization: Bearer $access_token"
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) throw new Exception("Vision API cURL error: " . curl_error($ch));
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $resp_json = json_decode($resp, true);
        if ($http_code !== 200 || !isset($resp_json['responses'][0])) {
            throw new Exception("Vision API failed: HTTP $http_code - " . $resp);
        }

        // parse labels
        $labels = $resp_json['responses'][0]['labelAnnotations'] ?? [];
        // build friendly result: map to our categories
        $detected = [];
        foreach ($labels as $l) {
            $desc = $l['description'];
            $score = $l['score'];
            $detected[] = ['desc' => $desc, 'score' => $score];
        }

        // map to our categories with a simple rule: first matching label wins
        $category = 'Unknown';
        $category_conf = 0.0;
        foreach ($detected as $d) {
            $lab = $d['desc'];
            $scr = $d['score'];
            if (isset($LABEL_MAP[$lab])) {
                $category = $LABEL_MAP[$lab];
                $category_conf = $scr;
                break;
            }
        }

        // fallback: try to infer by keywords (case-insensitive)
        if ($category === 'Unknown') {
            foreach ($detected as $d) {
                $lab = strtolower($d['desc']);
                if (strpos($lab, 'plastic') !== false || strpos($lab, 'bottle') !== false) {
                    $category = 'Plastic'; $category_conf = $d['score']; break;
                }
                if (strpos($lab, 'glass') !== false) {
                    $category = 'Glass'; $category_conf = $d['score']; break;
                }
                if (strpos($lab, 'can') !== false || strpos($lab, 'aluminum') !== false || strpos($lab, 'metal') !== false) {
                    $category = 'Metal'; $category_conf = $d['score']; break;
                }
                if (strpos($lab, 'paper') !== false || strpos($lab, 'cardboard') !== false) {
                    $category = 'Paper'; $category_conf = $d['score']; break;
                }
            }
        }

        $analysis_result = [
            'category' => $category,
            'confidence' => round($category_conf, 3),
            'labels' => $detected
        ];

    } catch (Exception $e) {
        $error_msg = $e->getMessage();
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SmartBin Demo - Vision API</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:Inter,Arial, sans-serif;background:#f6f7fb;color:#111;padding:24px}
.container{max-width:900px;margin:0 auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 6px 20px rgba(12,20,40,0.08)}
h1{margin:0 0 8px;font-size:20px}
label.button{display:inline-block;padding:10px 16px;background:#0b74ff;color:#fff;border-radius:6px;cursor:pointer}
.preview{margin-top:12px}
.result{margin-top:16px;padding:12px;background:#f1f6ff;border-radius:6px}
.small{font-size:13px;color:#555}
.bad{color:#b00020}
</style>
</head>
<body>
<div class="container">
  <h1>SmartBin — Quick Vision Demo</h1>
  <p class="small">Upload a photo (top-down) of an item. The demo calls Google Vision API and maps the label to one of 4 categories (Plastic, Glass, Metal, Paper).</p>

  <form method="post" enctype="multipart/form-data">
    <label class="button">Choose image
      <input type="file" name="image" accept="image/*" style="display:none" onchange="this.form.submit()">
    </label>
    <span class="small"> or drag & drop (not implemented)</span>
  </form>

  <?php if ($error_msg): ?>
    <div class="result bad"><strong>Error:</strong> <?=htmlspecialchars($error_msg)?></div>
  <?php endif; ?>

  <?php if ($analysis_result): ?>
    <div class="result">
      <div><strong>Detected category:</strong> <?=htmlspecialchars($analysis_result['category'])?> (confidence <?=htmlspecialchars($analysis_result['confidence'])?>)</div>
      <div style="margin-top:8px"><strong>Top labels:</strong></div>
      <ul>
        <?php foreach ($analysis_result['labels'] as $l): ?>
          <li><?=htmlspecialchars($l['desc'])?> — <?=round($l['score'],3)?></li>
        <?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <div style="margin-top:20px" class="small">Notes: this demo uses your service account JSON to request an access token. Keep your JSON private. For production, secure storage and server-side environment variables are recommended.</div>
</div>
</body>
</html>
