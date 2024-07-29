<?php

// Allow from any origin
if (isset($_SERVER['HTTP_ORIGIN'])) {
    // allow all origins
    header("Access-Control-Allow-Origin: *");
    header('Access-Control-Allow-Credentials: true');
}

// Access-Control headers are received during OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
    }
    if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {
        header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
    }
    exit(0);
}

// Trim trailing slashes and explode by '/'
$url = ltrim(rtrim($_SERVER['REQUEST_URI'], '/'), '/');
$validEndpoints = ["login", "details", "passwordchange", "logout"];

// Check if the endpoint is valid
if (!in_array($url, $validEndpoints)) {
    header('Content-Type: application/json');
    echo json_encode([
        "error" => 1,
        "msg" => "Endpoint not found",
        "data" => []
    ]);
    exit();
}

// Handle each endpoint
switch ($url) {
    case 'login':
        login();
        break;
    case 'details':
        details();
        break;
    case 'passwordchange':
        passwordChange();
        break;
    case 'logout':
        logout();
        break;
    default:
        http_response_code(500);
        echo json_encode([
            "error" => 1,
            "msg" => "Internal Server Error",
            "data" => []
        ]);
        break;
}

function login()
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        respondError("Invalid request method");
    }

    $users_file = 'users.json';
    $users = loadUsers($users_file);

    $input_data = json_decode(file_get_contents('php://input'), true);
    $email = $input_data['email'] ?? "";
    $password = $input_data['password'] ?? "";

    foreach ($users as $user_key => &$user) {
        if ($user['info']['email'] === $email && $user['info']['password'] === $password) {
            $new_login_token = base64_encode(random_bytes(32));
            $user['info']['token'] = $new_login_token;
            saveUsers($users_file, $users);
            respondSuccess([
                'token' => $new_login_token
            ]);
        }
    }

    respondError("Invalid email or password");
}

function details()
{
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        respondError("Authorization header not found");
    }

    $auth_header = $headers['Authorization'];
    list($type, $token) = explode(' ', $auth_header, 2);

    if ($type !== 'Bearer' || empty($token)) {
        respondError("Invalid token");
    }

    $users_file = 'users.json';
    $users = loadUsers($users_file);

    foreach ($users as &$user) {
        if ($user['info']['token'] === $token) {
            $data = $user;
            unset($data['info']['token']);
            unset($data['info']['password']);
            respondSuccess($data);
        }
    }

    respondError("Unauthorized access");
}

function passwordChange()
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        respondError("Invalid request method");
    }

    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        respondError("Authorization header not found");
    }

    $auth_header = $headers['Authorization'];
    list($type, $token) = explode(' ', $auth_header, 2);

    if ($type !== 'Bearer' || empty($token)) {
        respondError("Invalid token");
    }

    $json_data = file_get_contents('php://input');
    $requestData = json_decode($json_data, true);

    $current_password = $requestData['current_password'] ?? "";
    $new_password = $requestData['new_password'] ?? "";
    $confirm_password = $requestData['confirm_password'] ?? "";

    if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
        respondError("Current password, new password, and confirm password are required");
    }

    $users_file = 'users.json';
    $users = loadUsers($users_file);

    foreach ($users as $user_key => &$user) {
        if ($user['info']['token'] === $token) {
            if ($user['info']['password'] !== $current_password) {
                respondError("The current password does not match");
            }
            if ($new_password !== $confirm_password) {
                respondError("The new password and the confirm password do not match");
            }
            $user['info']['password'] = $new_password;
            saveUsers($users_file, $users);
            respondSuccess("Password successfully updated");
        }
    }

    respondError("Unauthorized access");
}

function logout()
{
    $headers = getallheaders();
    if (!isset($headers['Authorization'])) {
        respondError("Authorization header not found");
    }

    $auth_header = $headers['Authorization'];
    list($type, $token) = explode(' ', $auth_header, 2);

    if ($type !== 'Bearer' || empty($token)) {
        respondError("Invalid token");
    }

    $users_file = 'users.json';
    $users = loadUsers($users_file);

    foreach ($users as $user_key => &$user) {
        if ($user['info']['token'] === $token) {
            respondSuccess("Success");
        }
    }

    respondError("Unauthorized access");
}

function loadUsers($file)
{
    $json_data = file_get_contents($file);
    if ($json_data === false) {
        respondError("User data not found");
    }
    $users = json_decode($json_data, true);
    if ($users === null || json_last_error() !== JSON_ERROR_NONE) {
        respondError("Invalid user data format");
    }
    return $users;
}

function saveUsers($file, $users)
{
    file_put_contents($file, json_encode($users, JSON_PRETTY_PRINT));
}

function respondSuccess($data)
{
    header('Content-Type: application/json');
    echo json_encode([
        "error" => 0,
        "msg" => "Success",
        "data" => $data
    ]);
    exit();
}

function respondError($message)
{
    header('Content-Type: application/json');
    echo json_encode([
        "error" => 1,
        "msg" => $message,
        "data" => []
    ]);
    exit();
}
