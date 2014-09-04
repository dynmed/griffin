<?php
namespace Griffin;

class Route {
    function __construct() {
        $this->mysqli = new \mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
    }
    // handlers for supported HTTP request methods
    // subclasses must define handlers for request methods or 405 error will be returned
    public function get($trans) { $trans->stop(405, "Method Not Supported"); }
    public function post($trans) { $trans->stop(405, "Method Not Supported"); }
    public function put($trans) { $trans->stop(405, "Method Not Supported"); }
    public function delete($trans) { $trans->stop(405, "Method Not Supported"); }

    /**
     * Return whether or not the request is authorized
     *
     * @param  \Griffin\Transaction
     * @return bool
     */
    public function authorize($trans) { return False; }
}

class Record extends Route {
    public function get($trans) {
        $stmt = $this->mysqli->prepare("SELECT id, metadata, data FROM record WHERE id=?");
        if (!$stmt) {
            $trans->stop(500, "Internal Server Error");
        }
        // bind and fetch the requested record
        $id = (int) $trans->request_params["id"];
        $stmt->bind_param("i", $id);
        $stmt->execute();
        // You have to first call store_result for bind_result to work with a LONGTEXT
        // column. See: https://bugs.php.net/bug.php?id=47928
        $stmt->store_result();
        $stmt->bind_result($id, $metadata, $data);
        if ($stmt->fetch()) {
            $trans->response_code = 200;
            $trans->response_body = json_encode(
                array("id" => $id, "metadata" => $metadata, "data" => $data)
            );
            return;
        }
        // there was a problem fetching the requested data
        $trans->stop(404, "Resource Not Found");
    }

    public function post($trans) {
        // TODO can these validations be centralized somewhere for better auditing?
        // validate that the POST data is correctly formatted
        if (!property_exists($trans->request_data, "metadata")) {
            $trans->stop(400, "Invalid Request", "Missing Request Parameter: metadata");
        }
        if (!property_exists($trans->request_data, "data")) {
            $trans->stop(400, "Invalid Request", "Missing Request Parameter: data");
        }

        // TODO extract user_id from valid request token
        $stmt = $this->mysqli->prepare(
            'INSERT INTO `record` (`id`, `user_id`, `metadata`, `data`)
             VALUES (NULL, 0, ?, ?)'
        );

        $stmt->bind_param("ss", $trans->request_data->metadata,
                          $trans->request_data->data);
        if ($stmt->execute()) {
            $trans->response_code = 201;
            $trans->response_body = json_encode(
                array("status" => 201, "message" => "Record Created", "id" => $stmt->insert_id)
            );
            return;
        }
        // something went wrong with the insert
        $trans->stop(500, "Internal Server Error", "Unable to Create Record");
    }

    public function put($trans) {
        $stmt = $this->mysqli->prepare(
            "UPDATE `record` SET `metadata` = COALESCE(?, `metadata`),
                                 `data` = COALESCE(?, `data`)
             WHERE `id`=?"
        );
        $stmt->bind_param("ssi", $trans->request_data->metadata,
                          $trans->request_data->data,
                          $trans->request_params["id"]);
        if ($stmt->execute()) {
            $trans->response_code = 200;
            $trans->response_body = json_encode(
                array("status" => 200,
                      "message" => "Record Updated",
                      "id" => $trans->request_params["id"])
            );
            return;
        }
        // something went wrong with the update query
        $trans->stop(500, "Internal Server Error", "Unable to Update Record");
    }

    public function delete($trans) {
        // first check if this record exists before we try to delete it
        $id = (int) $trans->request_params["id"];
        $stmt = $this->mysqli->prepare("SELECT `id` FROM `record` WHERE id=?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $stmt->store_result();
        // no record with that id so return a 404
        if (!$stmt->num_rows) {
            $trans->stop(404, "Resource Not Found");
        }

        // we have a record by that id, so prepare the query to delete it
        $stmt = $this->mysqli->prepare("DELETE FROM `record` WHERE `id`=?");
        $stmt->bind_param("i", $id);
        if ($stmt->execute()) {
            $trans->response_code = 204;
            return;
        }
        // something went wrong running the delete query
        $trans->stop(500, "Internal Server Error", "Unable to Delete Record");
    }

    // TODO requires user table, request authentication keys, etc.
    public function authorize($trans) {
        switch (strtolower($trans->request_method)) {
        case "get":
        case "post":
        case "put":
        case "delete":
        }
        return true;
    }
}
?>
