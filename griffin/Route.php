<?php
namespace Griffin;

class Route {
    // handlers for supported HTTP request methods
    // subclasses must define these methods or 405 error will be returned
    public function get($trans) { $this->method_not_supported($trans); }
    public function post($trans) { $this->method_not_supported($trans); }
    public function put($trans) { $this->method_not_supported($trans); }
    public function delete($trans) { $this->method_not_supported($trans); }
    public function method_not_supported($trans) {
        $trans->response_code = 405;
        $trans->response_body = json_encode(array("message" => "method not supported"));
    }

    function __construct() {
        $this->mysqli = new \mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

    }
}

class Foo extends Route {
    public function get($trans) {
        $stmt = $this->mysqli->prepare("SELECT id, data FROM item WHERE id=?");
        if ($stmt) {
            $fid = (int) $trans->request_params["fid"];
            $stmt->bind_param("i", $fid);
            $stmt->execute();
            $stmt->bind_result($id, $data);
            if ($stmt->fetch()) {
                $trans->response_code = 200;
                $trans->response_body = json_encode(
                    array("fid" => $id, "data" => $data)
                );
                return;
            }
        }
        // weren't able to find it
        $trans->response_code = 404;
        $trans->response_body = json_encode(array("message" => "resource not found"));
        return;
    }

    public function post($trans) {
        $stmt = $this->mysqli->prepare("INSERT INTO item(data) VALUES(`?`");
        print_r($trans->request_data);
        exit;
        $data = $trans->request_params["data"];
        $stmt->bind_param("s", $data);
        $stmt->execute();
        $stmt->bind_result($data);
    }
}
?>
