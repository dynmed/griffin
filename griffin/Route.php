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

    // TODO make error messages more generic
    public function authorize($trans) {
        // basic formatting requirements for the Authorization header
        $auth_parts = preg_split("/[\s:]+/", trim($_SERVER["HTTP_AUTHORIZATION"]));
        if (count($auth_parts) != 3) {
            $trans->stop(401, "Unauthorized", "Incorrect Auth Format");
        }
        $scheme = $auth_parts[0];
        $user = $auth_parts[1];
        $signature = $auth_parts[2];
        // correct auth scheme
        if ($scheme != "Griffin") {
            $trans->stop(401, "Unauthorized", "Invalid Authorization Scheme");
        }
        // valid username format
        // TODO this is probably a redundant check since we check the actual
        // email address next
        if (!filter_var($user, FILTER_VALIDATE_EMAIL)) {
            $trans->stop(401, "Unauthorized", "Invalid Username Format");
        }
        // this username is registered and active
        // TODO add active bool column to user
        $stmt = $this->mysqli->prepare("SELECT id, pubkey FROM user WHERE email=?");
        $stmt->bind_param("s", $user);
        $stmt->execute();
        $stmt->store_result();
        $stmt->bind_result($uid, $pubkey);
        if ($stmt->fetch()) {
            $trans->request_uid = $uid;
        }
        else {
            $trans->stop(401, "Unauthorized", "Invalid Username");
        }
        // auth contains a signature
        if (!strlen($signature)) {
            $trans->stop(401, "Unauthorized", "Signature Missing");
        }
        // validate the signature on the request
        $signed_data = \Sodium::crypto_sign_open(base64_decode($signature),
                                                 base64_decode($pubkey));
        if ($signed_data === FALSE) {
            $trans->stop(401, "Unauthorized", "Invalid Signature");
        }
        // we have a valid signature, make sure it matches the request fields
        $signed_fields = json_decode($signed_data);
        // make sure signature is formatted as JSON
        if (!$signed_fields) {
            $trans->stop(401, "Unauthorized", "Invalid Signed JSON");
        }

        // check that each of the signed fields matches the request details
        // request path
        if ($signed_fields->path !== $trans->app_root.$trans->request_path) {
            $trans->stop(401, "Unauthorized", "Signature Does Not Match Request Path");
        }
        // request method
        if ($signed_fields->method !== $trans->request_method) {
            $trans->stop(401, "Unauthorized", "Signature Does Not Match Request Method");
        }
        // request content-type
        if ($signed_fields->content_type !== $trans->request_content_type) {
            $trans->stop(401, "Unauthorized", "Signature Does Not Match Content Type");
        }
        // request data
        if ($signed_fields->data !== $trans->raw_request_data) {
            $trans->stop(401, "Unauthorized", "Signature Does Not Match Request Data");
        }

        // all the signed fields are valid, check that the signature has not expired
        // Note: `time()` returns epoch relative to GMT
        if ((int)$signed_fields->expires < time()) {
            $trans->stop(401, "Unauthorized", "Signature is Expired");
        }

        switch (strtolower($trans->request_method)) {
            // GET, PUT, and DELETE all operate on a single record identified by
            // the id parameter. Authorization for all three means making sure the
            // requesting user is the owner of that record.
            case "get":
            case "put":
            case "delete":
                $id = (int) $trans->request_params["id"];
                // TODO is it really $trans->route or is it just $this? We might have
                // a cycle here.
                $stmt = $trans->route->mysqli->prepare(
                    "SELECT r.id FROM user AS u INNER JOIN record AS r ON u.id = r.user_id
                     WHERE u.email=? and r.id=?;"
                );
                $stmt->bind_param("si", $user, $id);
                $stmt->execute();
                $stmt->store_result();
                // requesting user is not the owner of this record
                if (!$stmt->num_rows) {
                    $trans->stop(401, "Unauthorized", "User Not Authorized");
                }
                break;
            case "post":
                break;
        }
        return true;
    }
}
?>
