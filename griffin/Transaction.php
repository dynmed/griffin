<?php
namespace Griffin;

// simple logger function
function log($msg) {
    if (is_null(APP_LOG)) {
        return;
    }
    $fp = fopen(APP_LOG, "a");
    fwrite($fp, sprintf("[%s] %s\n", date("Y-m-d H:i:s"), $msg));
    fclose($fp);
}

require "Route.php";

class Transaction {
    // application root
    public $app_root;

    // UID of requesting user
    public $request_uid;

    // request method
    public $request_method;

    // request content-type
    public $request_content_type;

    // request path relative to the application root
    public $request_path;

    // request paramaters
    public $request_params;

    // request data (POST or PUT) as JSON
    public $request_data;

    // request data (POST or PUT) exactly as sent
    public $raw_request_data;

    // Route class to handle the request
    public $route;

    // HTTP response code
    public $response_code;

    // response body
    public $response_body;

    // URL patterns to route requests
    private $urls = array(
        "/^\/record\/(?P<id>\d+)$/" => "\Griffin\Record",
        "/^\/record\/?$/" => "\Griffin\Record",
        "/^\/user\/?$/" => "\Griffin\User",
        "/^\/secret\/(?P<seconds>\d+)\/?$/" => "\Griffin\Secret",
        "/^\/secret\/?$/" => "\Griffin\Secret",
        "/^\/sync\/?$/" => "\Griffin\Sync"
    );

    function __construct() {
        $this->app_root = preg_replace("/\/index.php$/", "", $_SERVER["DOCUMENT_URI"]);
        $this->request_method = $_SERVER["REQUEST_METHOD"];
        $this->request_content_type = $_SERVER["CONTENT_TYPE"];
        $this->request_path = substr($_SERVER["REQUEST_URI"], strlen($this->app_root));

        // parse the request for route and parameters
        foreach ($this->urls as $regex => $class) {
            if (preg_match($regex, $this->request_path, $matches)) {
                $this->route = new $class;
                $this->request_params = $matches;
                break;
            }
        }

        // store any POST or PUT data
        if ((int) $_SERVER["CONTENT_LENGTH"]) {
            // validate request data as well-formed JSON
            $this->request_data = json_decode(file_get_contents("php://input"));
            if (!$this->request_data) {
                $this->stop(400, "Invalid Request", "Invalid JSON Format");
            }
            $this->raw_request_data = file_get_contents("php://input");
        }
    }

    public function dispatch() {
        // we couldn't find a route for this request
        if (!isset($this->route)) {
            $this->stop(400, "Invalid Request", "No Route Found");
        }
        // we have a route but it doesn't support the request method
        else if (!method_exists($this->route, $this->request_method)) {
            $this->stop(405, "Method Not Supported");
        }
        // we found a valid route, now make sure the request is authorized
        if (!$this->route->authorize($this)) {
            $this->stop(401, "Unauthorized");
        }
        // dispatch the request to the appropriate route
        call_user_func(array($this->route, $this->request_method), $this);
    }

    // send response code and message and stop processing immediately
    public function stop($response_code, $message, $details = "") {
        $this->response_code = $response_code;
        $response_body = array("status" => $response_code, "message" => $message);
        // include any optional details in the response
        if ($details) {
            $response_body["details"] = $details;
        }
        $this->response_body = json_encode($response_body);
        $this->respond();
        // don't process the request any further
        exit;
    }

    public function respond() {
        $this->status_line();
        if (strlen($this->response_body)) {
            echo $this->response_body . "\n";
        }
    }

    private function status_line() {
        switch ($this->response_code) {
        case 200:
            header($_SERVER["SERVER_PROTOCOL"]." 200 OK", true, 200);
            break;
        case 201:
            header($_SERVER["SERVER_PROTOCOL"]." 201 Created", true, 201);
            break;
        case 204:
            header($_SERVER["SERVER_PROTOCOL"]." 204 No Content", true, 204);
            break;
        case 400:
            header($_SERVER["SERVER_PROTOCOL"]." 400 Bad Request", true, 400);
            break;
        case 401:
            header($_SERVER["SERVER_PROTOCOL"]." 401 Unauthorized", true, 401);
            break;
        case 404:
            header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
            break;
        case 405:
            header($_SERVER["SERVER_PROTOCOL"]." 405 Method Not Allowed", true, 405);
            break;
        case 500:
            header($_SERVER["SERVER_PROTOCOL"]." 500 Internal Server Error", true, 500);
            break;
        }
    }

    public function log($msg) {
        file_put_contents("/tmp/griffin.log", $msg . "\n", FILE_APPEND);
    }
}
?>
