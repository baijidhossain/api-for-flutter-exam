<?php


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://baijid.dev.alpha.net.bd/details?login_token=bf0eed3caf06e2d29e6353689d5c4fe5");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Disable SSL verification
$response = curl_exec($ch);
if ($response === false) {
  $error = curl_error($ch);
  echo "cURL Error: $error";
} else {
  echo "Response: $response";
}
curl_close($ch);
