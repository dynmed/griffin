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
}

class Foo extends Route {
    public function get($trans) {
        $trans->response_code = 200;
        $trans->response_body = json_encode(
            array("fid" => (int) $trans->request_params["fid"])
        );
    }
}
?>
