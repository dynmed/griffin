<?php
namespace Griffin;
require "Route.php";

class Transaction {
    // application root
    public $app_root;

    // request method
    // TODO probably don't need to store this ourselves ($_SERVER["REQUEST_METHOD"])
    public $request_method;

    // request path relative to the application root
    public $request_path;

    // request paramaters
    public $request_params;

    // Route class to handle the request
    public $route;

    // URL patterns to route requests
    private $urls = array(
        "/^\/foo\/(?P<fid>\d+)/" => "\Griffin\Foo",
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
    }

    function dispatch() {
        call_user_func(array($this->route, $this->request_method));
    }
}
?>
