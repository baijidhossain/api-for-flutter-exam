<?php


$json_users_file = 'users.json';


// Read JSON file
$json_data = file_get_contents($json_users_file);

// Decode JSON data into associative array
$users = json_decode($json_data, true);


$url = $_GET['url'] ?? "";


// Trim trailing slashes and explode by '/'
$url = rtrim($url, '/');
$urlParts = explode('/', $url);

// Define valid endpoints
$validEndpoints = ["login", "details", "passwordchange"];

// Check if the URL contains more than one part
if (count($urlParts) > 1) {
  // Bad request
  http_response_code(400);
  echo json_encode(array("msg" => "Bad Request: Invalid URL structure"));
  exit(); // Stop further execution
}

// Check if the endpoint is valid
$requestedEndpoint = $urlParts[0] ?? '';
if (!in_array($requestedEndpoint, $validEndpoints)) {
  // Invalid endpoint
  http_response_code(404);
  echo json_encode(array("msg" => "Not Found: Endpoint not supported"));
  exit(); // Stop further execution
}

// Handle each endpoint
switch ($requestedEndpoint) {
  case 'login':
    // Handle login endpoint
    login();
    break;
  case 'details':
    // Handle details endpoint
    details();
    break;
  case 'passwordchange':
    // Handle passwordchange endpoint
    passwordChange();
    break;
  default:
    // Should not reach here if validEndpoints array is correctly defined
    http_response_code(500);
    echo json_encode(array("msg" => "Internal Server Error"));
    break;
}

function login()
{
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(array("error" => "1", "msg" => "Invalid request method"));
    exit();
  }

  $users_file = 'users.json';
  $json_data = file_get_contents($users_file);
  $users = json_decode($json_data, true);

  if ($users === null && json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    header('Content-Type: application/json');
    $user_data = [
      "error" => 1,
      "msg" => "User data not found!",
      "data" => []
    ];

    echo json_encode($user_data);
    exit();
  }

  $input_data = json_decode(file_get_contents('php://input'), true);
  $email = $input_data['email'] ?? "";
  $password = $input_data['password'] ?? "";

  foreach ($users as $user_key => $data) {

    $user = $data['info'];

    if ($user['email'] === $email && $user['password'] === $password) {

      $new_login_token =  base64_encode(random_bytes(32));

      $user['token'] = $new_login_token;

      $users[$user_key]['info'] = $user;

      file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));

      http_response_code(400);
      header('Content-Type: application/json');
      $user_data = [
        "error" => 0,
        "msg" => "Success",
        "data" => [
          'token' => $new_login_token
        ]
      ];

      echo json_encode($user_data);
      exit();
    }
  }

  http_response_code(400);
  header('Content-Type: application/json');
  $user_data = [
    "error" => 1,
    "msg" => "Invalid email or password",
    "data" => []
  ];
  echo json_encode($user_data);

  exit();
}

function details()
{

  ini_set('display_errors', 1);
  error_reporting(E_ALL);

  $headers = getallheaders();
  if (!isset($headers['Authorization'])) {
    http_response_code(401);
    header('Content-Type: application/json');
    $user_data = [
      "error" => 1,
      "msg" => "Authorization header not found",
      "data" => []
    ];
    echo json_encode($user_data);
    exit();
  }


  $auth_header = $headers['Authorization'];
  list($type, $token) = explode(' ', $auth_header, 2);

  if ($type !== 'Bearer' || empty($token)) {
    http_response_code(401);
    header('Content-Type: application/json');
    $user_data = [
      "error" => 1,
      "msg" => "Invalid token",
      "data" => []
    ];
    echo json_encode($user_data);
    exit();
  }

  $users_file = 'users.json';
  $json_data = file_get_contents($users_file);
  $users = json_decode($json_data, true);
  $validate_token = false;

  foreach ($users as $key => $data) {

    $validate_token = true;

    if ($data['info']['token'] === $token) {

      unset($data['info']['token']);
      unset($data['info']['password']);

      http_response_code(200);
      header('Content-Type: application/json');
      $user_data = [
        "error" => 0,
        "msg" => "success",
        "data" => $data
      ];

      echo json_encode($user_data);
      exit();
    }
  }

  // Invalid token
  if (!$validate_token) {
    http_response_code(401);
    header('Content-Type: application/json');
    $response = [
      "error" => 1,
      "msg" => "Unauthorized access",
      "data" => []
    ];
    echo json_encode($response);
    exit();
  }

  http_response_code(401);
  header('Content-Type: application/json');
  $user_data = [
    "error" => 1,
    "msg" => "Invalid token",
    "data" => []
  ];
  echo json_encode($user_data);
  exit();
}

function passwordChange()
{
  // Ensure errors are displayed during debugging
  ini_set('display_errors', 1);
  error_reporting(E_ALL);

  // Check if Authorization header exists
  $headers = getallheaders();
  if (!isset($headers['Authorization'])) {
    http_response_code(401);
    header('Content-Type: application/json');
    $response = [
      "error" => 1,
      "msg" => "Authorization header not found",
      "data" => []
    ];
    echo json_encode($response);
    exit();
  }

  // Extract token from Authorization header
  $auth_header = $headers['Authorization'];
  list($type, $token) = explode(' ', $auth_header, 2);

  // Validate Bearer token format
  if ($type !== 'Bearer' || empty($token)) {
    http_response_code(401);
    header('Content-Type: application/json');
    $response = [
      "error" => 1,
      "msg" => "Invalid token",
      "data" => []
    ];
    echo json_encode($response);
    exit();
  }

  // Read JSON input data
  $json_data = file_get_contents('php://input');
  $requestData = json_decode($json_data, true);

  // Validate required fields
  $current_password = isset($requestData['current_password']) ? $requestData['current_password'] : "";
  $new_password = isset($requestData['new_password']) ? $requestData['new_password'] : "";
  $confirm_password = isset($requestData['confirm_password']) ? $requestData['confirm_password'] : "";

  if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
    http_response_code(400);
    header('Content-Type: application/json');
    $response = [
      "error" => 1,
      "msg" => "Current password, new password, and confirm password are required",
      "data" => []
    ];
    echo json_encode($response);
    exit();
  }

  // Load users data from file
  $users_file = 'users.json';
  $json_data = file_get_contents($users_file);
  $users = json_decode($json_data, true);

  $validate_token = false;

  // Find user by token and validate passwords
  foreach ($users as $user_key => &$user) {
    if ($user['info']['token'] === $token) {
      $validate_token = true;

      if ($user['info']['password'] !== $current_password) {
        http_response_code(401);
        header('Content-Type: application/json');
        $response = [
          "error" => 1,
          "msg" => "The current password does not match",
          "data" => []
        ];
        echo json_encode($response);
        exit();
      }

      if ($new_password !== $confirm_password) {
        http_response_code(401);
        header('Content-Type: application/json');
        $response = [
          "error" => 1,
          "msg" => "The new password and the confirm password do not match",
          "data" => []
        ];
        echo json_encode($response);
        exit();
      }

      // Update user's password and save back to file
      $user['info']['password'] = $new_password;
      file_put_contents($users_file, json_encode($users, JSON_PRETTY_PRINT));

      http_response_code(200);
      header('Content-Type: application/json');
      $response = [
        "error" => 0,
        "msg" => "Password successfully updated",
        "data" => []
      ];
      echo json_encode($response);
      exit();
    }
  }

  // Invalid token
  if (!$validate_token) {
    http_response_code(401);
    header('Content-Type: application/json');
    $response = [
      "error" => 401,
      "msg" => "Unauthorized access",
      "data" => []
    ];
    echo json_encode($response);
    exit();
  }

  // If no user found with the provided token
  http_response_code(401);
  header('Content-Type: application/json');
  $response = [
    "error" => 1,
    "msg" => "Password update failed!",
    "data" => []
  ];
  echo json_encode($response);
  exit();
}
