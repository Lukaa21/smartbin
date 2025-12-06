<?php
// index.php - SmartBin - Prepoznavanje objekata za reciklažu
// Google Vision API integration using Service Account JSON and JWT OAuth2 exchange

// ----- CONFIG -----
$SERVICE_ACCOUNT_FILE = __DIR__ . '/keys/thermal-shuttle-480412-g1-ab7833ab300c.json';
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

// Lista irelevantnih labela koje treba ignorisati (brendovi, logovi, dizajn ambalaze)
$IRRELEVANT_LABELS = [
    'Logo',
    'Brand',
    'Font',
    'Graphics',
    'Label',
    'Packaging and labeling',
    'Trademark',
    'Advertising',
    'Signage',
    'Symbol',
    'Circle',
    'Rectangle',
    'Design',
    'Art',
    'Graphic design',
    'Illustration',
    'Pattern',
    'Text',
    'Number',
    'Letter',
    'Word',
    'Barcode',
    'QR code',
    'Product',
    'Electric blue'
];

// utility: base64url encode
function base64url_encode($data)
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// create JWT and exchange for access token
function get_access_token_from_service_account($service_account_file)
{
    global $OAUTH_TOKEN_URI;

    if (!file_exists($service_account_file)) {
        throw new Exception("Service account file not found: $service_account_file");
    }

    $sa = json_decode(file_get_contents($service_account_file), true);
    if (!$sa)
        throw new Exception("Invalid service account JSON.");

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
$uploaded_image = null;

// Start session to store uploaded image
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!isset($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
            throw new Exception("Upload failed or no file uploaded.");
        }

        $tmpname = $_FILES['image']['tmp_name'];
        $img_data = file_get_contents($tmpname);
        $base64 = base64_encode($img_data);

        // Store image data in session for display
        $_SESSION['uploaded_image'] = 'data:' . $_FILES['image']['type'] . ';base64,' . $base64;

        // get access token
        $access_token = get_access_token_from_service_account($SERVICE_ACCOUNT_FILE);

        // build Vision API request - koristimo i OBJECT_LOCALIZATION za bolje prepoznavanje glavnog objekta
        $request_body = [
            "requests" => [
                [
                    "image" => ["content" => $base64],
                    "features" => [
                        ["type" => "LABEL_DETECTION", "maxResults" => 20],
                        ["type" => "OBJECT_LOCALIZATION", "maxResults" => 5]
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
        if ($resp === false)
            throw new Exception("Vision API cURL error: " . curl_error($ch));
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $resp_json = json_decode($resp, true);
        if ($http_code !== 200 || !isset($resp_json['responses'][0])) {
            throw new Exception("Vision API failed: HTTP $http_code - " . $resp);
        }

        // parse labels i filtriraj irelevantne
        $labels = $resp_json['responses'][0]['labelAnnotations'] ?? [];
        $objects = $resp_json['responses'][0]['localizedObjectAnnotations'] ?? [];

        // Filtriraj labele - ukloni brendove, logove i slicno
        $detected = [];
        foreach ($labels as $l) {
            $desc = $l['description'];
            $score = $l['score'];

            // Provjeri da li je labela irelevantna
            $is_irrelevant = false;
            foreach ($IRRELEVANT_LABELS as $irrelevant) {
                if (stripos($desc, $irrelevant) !== false || $desc === $irrelevant) {
                    $is_irrelevant = true;
                    break;
                }
            }

            // Dodaj samo relevantne labele
            if (!$is_irrelevant) {
                $detected[] = ['desc' => $desc, 'score' => $score];
            }
        }

        // Dodaj i detektovane objekte (glavni objekti na slici)
        $detected_objects = [];
        foreach ($objects as $obj) {
            $detected_objects[] = [
                'name' => $obj['name'],
                'score' => $obj['score']
            ];
        }

        // map to our categories - prvo pokusaj sa objektima, pa sa labelama
        $category = 'Unknown';
        $category_conf = 0.0;
        $matched_item = '';

        // Prvo provjeri detektovane objekte (glavni objekti)
        foreach ($detected_objects as $obj) {
            $lab = $obj['name'];
            $scr = $obj['score'];
            if (isset($LABEL_MAP[$lab])) {
                $category = $LABEL_MAP[$lab];
                $category_conf = $scr;
                $matched_item = $lab;
                break;
            }
        }

        // Ako nije pronadjen u objektima, provjeri labele
        if ($category === 'Unknown') {
            foreach ($detected as $d) {
                $lab = $d['desc'];
                $scr = $d['score'];
                if (isset($LABEL_MAP[$lab])) {
                    $category = $LABEL_MAP[$lab];
                    $category_conf = $scr;
                    $matched_item = $lab;
                    break;
                }
            }
        }

        // fallback: try to infer by keywords (case-insensitive)
        if ($category === 'Unknown') {
            foreach ($detected as $d) {
                $lab = strtolower($d['desc']);
                if (strpos($lab, 'plastic') !== false || strpos($lab, 'bottle') !== false) {
                    $category = 'Plastic';
                    $category_conf = $d['score'];
                    $matched_item = $d['desc'];
                    break;
                }
                if (strpos($lab, 'glass') !== false) {
                    $category = 'Glass';
                    $category_conf = $d['score'];
                    $matched_item = $d['desc'];
                    break;
                }
                if (strpos($lab, 'can') !== false || strpos($lab, 'aluminum') !== false || strpos($lab, 'metal') !== false) {
                    $category = 'Metal';
                    $category_conf = $d['score'];
                    $matched_item = $d['desc'];
                    break;
                }
                if (strpos($lab, 'paper') !== false || strpos($lab, 'cardboard') !== false) {
                    $category = 'Paper';
                    $category_conf = $d['score'];
                    $matched_item = $d['desc'];
                    break;
                }
            }
        }

        $analysis_result = [
            'category' => $category,
            'confidence' => round($category_conf, 3),
            'matched_item' => $matched_item,
            'labels' => $detected,
            'objects' => $detected_objects
        ];

    } catch (Exception $e) {
        $error_msg = $e->getMessage();
    }
}

// Retrieve uploaded image from session
if (isset($_SESSION['uploaded_image'])) {
    $uploaded_image = $_SESSION['uploaded_image'];
}
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>SmartBin - Prepoznavanje Objekata za Reciklažu</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #111;
            padding: 24px;
            min-height: 100vh;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            padding: 32px;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
        }

        h1 {
            margin: 0 0 12px;
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .subtitle {
            font-size: 14px;
            color: #666;
            margin-bottom: 24px;
            line-height: 1.6;
        }

        label.button {
            display: inline-block;
            padding: 14px 28px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }

        label.button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }

        .upload-section {
            margin-bottom: 24px;
            padding-bottom: 24px;
            border-bottom: 2px solid #f0f0f0;
        }

        .result-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-top: 24px;
        }

        @media (max-width: 768px) {
            .result-container {
                grid-template-columns: 1fr;
            }
        }

        .image-preview {
            background: #f8f9fa;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .image-preview img {
            width: 100%;
            height: auto;
            display: block;
        }

        .analysis-panel {
            background: #f8f9fa;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .category-badge {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .category-Plastic {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
        }

        .category-Glass {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
            color: white;
        }

        .category-Metal {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
            color: white;
        }

        .category-Paper {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
            color: white;
        }

        .category-Unknown {
            background: #9e9e9e;
            color: white;
        }

        .info-row {
            margin: 12px 0;
            padding: 12px;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .info-label {
            font-weight: 600;
            color: #555;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }

        .info-value {
            font-size: 16px;
            color: #111;
        }

        .confidence-bar {
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.5s ease;
        }

        .labels-list {
            margin-top: 16px;
        }

        .labels-list h3 {
            font-size: 14px;
            font-weight: 600;
            color: #555;
            margin-bottom: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .label-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: white;
            margin-bottom: 6px;
            border-radius: 6px;
            font-size: 14px;
        }

        .label-name {
            color: #333;
        }

        .label-score {
            color: #667eea;
            font-weight: 600;
        }

        .recycling-info {
            margin-top: 20px;
            padding: 16px;
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .recycling-info h3 {
            font-size: 16px;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 8px;
        }

        .recycling-info p {
            font-size: 14px;
            color: #555;
            line-height: 1.6;
        }

        .error-message {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
            padding: 16px 20px;
            border-radius: 8px;
            margin-top: 16px;
            font-weight: 500;
        }

        .small-note {
            margin-top: 24px;
            padding-top: 24px;
            border-top: 2px solid #f0f0f0;
            font-size: 12px;
            color: #999;
            line-height: 1.6;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>🗑️ SmartBin - Prepoznavanje Objekata</h1>
        <p class="subtitle">Uploadujte sliku objekta koji želite da reciklirate. Sistem će automatski prepoznati objekat
            i odrediti u koju kategoriju reciklaže spada.</p>

        <div class="upload-section">
            <form method="post" enctype="multipart/form-data">
                <label class="button">📷 Izaberite Sliku
                    <input type="file" name="image" accept="image/*" style="display:none" onchange="this.form.submit()">
                </label>
            </form>
        </div>

        <?php if ($error_msg): ?>
            <div class="error-message"><strong>⚠️ Greška:</strong> <?= htmlspecialchars($error_msg) ?></div>
        <?php endif; ?>

        <?php if ($analysis_result && $uploaded_image): ?>
            <div class="result-container">
                <!-- Prikaz slike -->
                <div class="image-preview">
                    <img src="<?= htmlspecialchars($uploaded_image) ?>" alt="Uploadovana slika">
                </div>

                <!-- Analiza -->
                <div class="analysis-panel">
                    <div class="category-badge category-<?= htmlspecialchars($analysis_result['category']) ?>">
                        <?= htmlspecialchars($analysis_result['category']) ?>
                    </div>

                    <div class="info-row">
                        <div class="info-label">Prepoznat Objekat</div>
                        <div class="info-value">
                            <?= htmlspecialchars($analysis_result['matched_item'] ?: 'N/A') ?>
                        </div>
                    </div>

                    <div class="info-row">
                        <div class="info-label">Pouzdanost Prepoznavanja</div>
                        <div class="info-value">
                            <?= round($analysis_result['confidence'] * 100, 1) ?>%
                        </div>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: <?= round($analysis_result['confidence'] * 100) ?>%">
                            </div>
                        </div>
                    </div>

                    <?php
                    // Informacije o reciklaži za svaku kategoriju
                    $recycling_tips = [
                        'Plastic' => 'Plastika se reciklira u ŽUTOM kontejneru. Obavezno isperite ambalažu i uklonite čepove prije bacanja.',
                        'Glass' => 'Staklo se reciklira u ZELENOM kontejneru. Staklo se može reciklirati beskonačno puta bez gubitka kvaliteta.',
                        'Metal' => 'Metal (limenke, konzerve) se reciklira u PLAVOM kontejneru. Isperite prije bacanja.',
                        'Paper' => 'Papir i karton se recikliraju u PLAVOM kontejneru. Nemojte bacati masni ili mokri papir.',
                        'Unknown' => 'Objekat nije prepoznat. Molimo pokušajte sa jasnijom slikom ili kontaktirajte lokalni centar za reciklažu.'
                    ];
                    ?>

                    <?php if (isset($recycling_tips[$analysis_result['category']])): ?>
                        <div class="recycling-info">
                            <h3>♻️ Informacije o Reciklaži</h3>
                            <p><?= $recycling_tips[$analysis_result['category']] ?></p>
                        </div>
                    <?php endif; ?>

                    <!-- Relevantne labele (samo top 5) -->
                    <?php if (!empty($analysis_result['labels'])): ?>
                        <div class="labels-list">
                            <h3>🔍 Detektirane Karakteristike</h3>
                            <?php
                            $top_labels = array_slice($analysis_result['labels'], 0, 5);
                            foreach ($top_labels as $l):
                                ?>
                                <div class="label-item">
                                    <span class="label-name"><?= htmlspecialchars($l['desc']) ?></span>
                                    <span class="label-score"><?= round($l['score'] * 100, 1) ?>%</span>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <div class="small-note">
            <strong>Napomena:</strong> Ovaj sistem koristi Google Vision API za prepoznavanje objekata.
            Tačnost prepoznavanja zavisi od kvaliteta slike i uslova osvetljenja.
            Za najbolje rezultate, slikajte objekat na svetloj pozadini sa dobrim osvetljenjem.
        </div>
    </div>
</body>

</html>