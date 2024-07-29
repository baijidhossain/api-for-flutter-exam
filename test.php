<?php

$curl = curl_init();

curl_setopt_array($curl, array(
  CURLOPT_URL => 'https://flutter.vmx.link/details',
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_ENCODING => '',
  CURLOPT_MAXREDIRS => 10,
  CURLOPT_TIMEOUT => 0,
  CURLOPT_FOLLOWLOCATION => true,
  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
  CURLOPT_CUSTOMREQUEST => 'GET',
  CURLOPT_HTTPHEADER => array(
    'Authorization: Bearer RcSVfvFM3ZoJfLwrQ15z4SdeG76BYddxT09PmYKrJvw='
  ),
  CURLOPT_SSL_VERIFYPEER => false, // Disable SSL verification
  CURLOPT_SSL_VERIFYHOST => false  // Disable host verification
));

$response = curl_exec($curl);

if (curl_errno($curl)) {
  echo 'Curl error: ' . curl_error($curl);
} else {
  $http_status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
  if ($http_status == 200) {
    echo $response;
  } else {
    echo 'HTTP Status Code: ' . $http_status . "\n";
    echo 'Response: ' . $response . "\n";
  }
}

curl_close($curl);
