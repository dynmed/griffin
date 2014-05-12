<?php
namespace Griffin;
require "Route.php";

class Transaction {
    // application root
    public $app_root;

    // request method
    public $request_method;

    // request path relative to the application root
    public $request_path;

    // request paramaters
    public $request_params;

    // request data (POST or PUT)
    public $request_data;

    // Route class to handle the request
    public $route;

    // HTTP response code
    public $response_code;

    // response body
    public $response_body;

    // URL patterns to route requests
    private $urls = array(
        "/^\/foo\/(?P<fid>\d+)$/" => "\Griffin\Foo",
        "/^\/foo\/$/" => "\Griffin\Foo",
    );

    function __construct() {
        $this->app_root = preg_replace("/\/index.php$/", "", $_SERVER["DOCUMENT_URI"]);
        $this->request_method = $_SERVER["REQUEST_METHOD"];
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
        // TODO need to parse this as JSON
        $this->request_data = file_get_contents("php://input");
    }

    public function dispatch() {
        // we couldn't find a route for this request
        // TODO this is probably a 400
        if (!isset($this->route)) {
            $this->response_code = 404;
            $this->response_body = json_encode(array("message" => "resource not found"));
        }
        // we have a route but it doesn't support the request method
        else if (!method_exists($this->route, $this->request_method)) {
            $this->route->method_not_supported($this);
        }
        // dispatch the request to the appropriate route
        else {
            call_user_func(array($this->route, $this->request_method), $this);
        }
    }

    public function respond() {
        $this->status_line();
        echo $this->response_body . "\n";
    }

    private function status_line() {
        switch($this->response_code) {
        case 200:
            header($_SERVER["SERVER_PROTOCOL"]." 200 OK", true, 200);
            break;
        case 404:
            header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
            break;
        case 405:
            header($_SERVER["SERVER_PROTOCOL"]." 405 Method Not Allowed", true, 405);
            break;
        }
    }
}
?>
