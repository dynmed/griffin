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
     * @param  \Griffin\Transaction $trans
     * @param  bool $check_signature
     * @return bool
     */
    // TODO this might be a bad name for this function if we only (sometimes)
    // use it for AuthZ and other times just use it to parse the request
    public function authorize($trans, $check_signature = True) {
        // basic formatting and signature checking for request
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
        if (!filter_var($user, FILTER_VALIDATE_EMAIL)) {
            $trans->stop(401, "Unauthorized", "Invalid Username Format");
        }
        // this username is registered and active
        $stmt = $this->mysqli->prepare(
            "SELECT id, pubkey FROM user WHERE email=? AND valid=TRUE"
        );
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

        // return early if the request doesn't require a signature
        if (!$check_signature) {
            return True;
        }

        /*
         * Do signature validations
         */

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

        // all validations pass
        return True;
    }
}

class Record extends Route {
    public function get($trans) {
        $stmt = $this->mysqli->prepare("SELECT id, metadata, data FROM record WHERE id=?");
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
        // prepared statement for creating a new record owned by the user we identified
        // during request authorization
        $stmt = $this->mysqli->prepare(
            'INSERT INTO `record` (`id`, `user_id`, `metadata`, `data`)
             VALUES (NULL, ?, ?, ?)'
        );

        $stmt->bind_param("iss", $trans->request_uid, $trans->request_data->metadata,
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
        // basic Authorization header validation
        parent::authorize($trans);

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

class Secret extends Route {
    // fetch secrets last updated within the past N seconds
    public function get($trans) {
        $seconds = (int) $trans->request_params["seconds"];
        // create the datetime used to query secrets
        if ($seconds == 0) {
            $datetime = "0000-00-00 00:00:00";
        }
        else {
            $datetime = "0000-00-00 00:00:00";
        }

        $stmt = $this->mysqli->prepare(
            'SELECT `id`, `key_id`, `schema`, `updated`, `uid`, `gid`, `data` FROM `secret`
             WHERE `uid`=? AND `updated`>=?;'
        );
        $stmt->bind_param("is", $trans->request_uid, $datetime);
        if ($stmt->execute()) {
            $stmt->store_result();
            $stmt->bind_result($id, $key_id, $schema, $updated, $uid, $gid, $data);
            $secrets = array();
            // TODO updated should be in terms of seconds ago
            while ($stmt->fetch()) {
                array_push(
                    $secrets,
                    array("id" => $id, "key_id" => $key_id, "schema" => $schema,
                          "updated" => $updated, "gid" => $gid, "data" => $data)
                );
            }
            $trans->response_code = 200;
            $trans->response_body = json_encode($secrets);
            return;
        }
        // something went wrong with the query
        $trans->stop(500, "Internal Server Error", "Unable to Service Request");
    }

    // create or update secrets
    public function post($trans) {
        // check signature on request
        parent::authorize($trans);

        // TODO property_exists pattern should be factored out and centralized
        // validate that `secrets` were sent and were formatted as an array
        if (!property_exists($trans->request_data, "secrets")) {
            $trans->stop(400, "Invalid Request", "Missing Request Parameter: secrets");
        }
        if (!is_array($trans->request_data->secrets)) {
            $trans->stop(400, "Invalid Request", "Param secrets should be array type");
        }

        // keep track of which secrets were created, updated, and skipped
        $created_secrets = array();
        $updated_secrets = array();
        $skipped_secrets = array();

        // look at each secret and update any that is fresher than the server copy
        foreach ($trans->request_data->secrets as $secret) {
            // skip any secrets that are improperly formatted, provide the secret
            // ID and reason for being skipped
            foreach(array("id", "key_id", "schema", "age") as $prop) {
                // verify that required fields for secret are present
                if (!property_exists($secret, $prop)) {
                    array_push($skipped_secrets,
                               array("id" => $secret->id,
                                     "error" => "Missing property: ".$prop)
                    );
                    // skip to the next secret (don't keep validating this one)
                    break 2;
                }
                // validate that secret fields are positive integers
                else if ((!is_int($secret->{$prop})) ||
                         ($secret->{$prop} <= 0)) {
                    array_push($skipped_secrets,
                               array("id" => $secret->id,
                                     "error" => "Invalid ".$prop.": ".$secret->{$prop})
                    );
                    // skip to the next secret (don't keep validating this one)
                    break 2;
                }
            }

            // determine if we're updating an existing secret or creating a new one
            $stmt = $this->mysqli->prepare(
                'SELECT `id`, `updated` FROM `secret` WHERE `id`=? AND `uid`=?;'
            );
            $stmt->bind_param("ss", $secret->id, $trans->request_uid);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($id, $server_updated);
            $stmt->fetch();
            // create a local timestamp based on the request secret age
            $client_updated = date("Y-m-d H:i:s",
                                   strtotime(sprintf("-%d seconds", $secret->age)));

            // existing secret with this ID, see if client or server version is newer
            if ($stmt->num_rows) {
                // client version has been updated more recently, so store the value
                if ($client_updated > $server_updated) {
                    $stmt = $this->mysqli->prepare(
                        'UPDATE `secret`
                         SET `key_id`=?, `schema`=?, `updated`=?, `data`=?
                         WHERE `id`=? AND `uid`=?;'
                    );
                    $stmt->bind_param("ssssss", $secret->key_id, $secret->schema,
                                      $client_updated, $secret->data, $secret->id,
                                      $trans->request_uid);
                    if ($stmt->execute()) {
                        array_push($updated_secrets, array("id" => $secret->id));
                    }
                }
                // server version is newer, skip performing the update
                else {
                    array_push($skipped_secrets,
                               array("id" => $secret->id,
                                     "msg" => "Server version is newer")
                    );
                }
            }

            // no secret with this ID, create it
            else {
                $stmt = $this->mysqli->prepare(
                    'INSERT INTO `secret` (`id`, `key_id`, `schema`, `updated`, `uid`, `data`)
                     VALUES (?, ?, ?, ?, ?, ?)'
                );
                $stmt->bind_param("iiisis", $secret->id, $secret->key_id,
                                  $secret->schema, $client_updated,
                                  $trans->request_uid, json_encode($secret->data));
                if ($stmt->execute()) {
                    array_push($created_secrets, array("id" => $secret->id));
                }
                else {
                    array_push($skipped_secrets, array("id" => $secret->id));
                }
            }
        }

        // 201 to indicate records were created, otherwise 200
        if (count($created_secrets)) {
            $trans->response_code = 201;
        }
        else {
            $trans->response_code = 200;
        }
        // return the lists of secrets that were created, updated, or skipped
        $trans->response_body = json_encode(
            array("status" => $trans->response_code, "created" => $created_secrets,
                  "updated" => $updated_secrets, "skipped" => $skipped_secrets)
        );
        return;
    }

    public function authorize($trans) {
        return parent::authorize($trans);
    }
}

class User extends Route {
    // register a new user
    public function post($trans) {
        // validate email address
        if (!property_exists($trans->request_data, "email")) {
            $trans->stop(400, "Invalid Request", "Missing Request Parameter: email");
        }
        $email = $trans->request_data->email;
        // valid email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $trans->stop(400, "Invalid Request", "Invalid Username Format");
        }
        // no duplicate email addresses
        $stmt = $this->mysqli->prepare("SELECT `id` FROM `user` WHERE `email`=?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows) {
            $trans->stop(400, "User Already Exists");
        }
        // validate pubkey
        if (!property_exists($trans->request_data, "pubkey")) {
            $trans->stop(400, "Invalid Request", "Missing Request Parameter: pubkey");
        }
        // prepared statement for creating a new record owned by the user we identified
        // during request authorization
        // TODO: implement email validation
        $stmt = $this->mysqli->prepare(
            'INSERT INTO `user` (`email`, `pubkey`, `valid`)
             VALUES (?, ?, True)'
        );

        $stmt->bind_param("ss", $email, $trans->request_data->pubkey);
        if ($stmt->execute()) {
            $trans->response_code = 201;
            $trans->response_body = json_encode(
                array("status" => 201, "message" => "User Created", "email" => $email)
            );
            return;
        }
        // something went wrong with the insert
        $trans->stop(500, "Internal Server Error", "Unable to Create User");        
    }

    // deregister a user
    public function delete($trans) {
        // parent::authorize() already validated that this user is registered
        // and active

        // delete all the secrets owned by this user
        $stmt = $this->mysqli->prepare('DELETE FROM `secret` WHERE `uid`=?;');
        $stmt->bind_param("i", $trans->request_uid);
        if (!$stmt->execute()) {
            $trans->stop(500, "Internal Server Error", "Unable to Delete Secrets");
        }

        // delete the user
        $stmt = $this->mysqli->prepare('DELETE FROM `user` WHERE `id`=?;');
        $stmt->bind_param("i", $trans->request_uid);
        if (!$stmt->execute()) {
            $trans->stop(500, "Internal Server Error", "Unable to Delete User");
        }

        // deregistration successful
        $trans->response_code = 200;
        $trans->response_body = json_encode(
            array("status" => 200,
                  "message" => "User Deregistered",
                  "id" => $trans->request_uid)
        );
        return;
    }

    public function authorize($trans) {
        // registering a new user doesn't require authorization (only email
        // validation)
        if ($trans->request_method == "POST") {
            return True;
        }
        // deregistration requires normal valid signature
        return parent::authorize($trans);
    }
}

class Sync extends Route {

    public function get($trans) {
        $stmt = $this->mysqli->prepare("SELECT data FROM sync WHERE uid=?");
        // bind and fetch the requested record
        $uid = (int) $trans->request_uid;
        $stmt->bind_param("i", $uid);
        $stmt->execute();
        // You have to first call store_result for bind_result to work with a LONGTEXT
        // column. See: https://bugs.php.net/bug.php?id=47928
        $stmt->store_result();
        $stmt->bind_result($data);
        if ($stmt->fetch()) {
            $trans->response_code = 200;
            $trans->response_body = json_encode( array("data" => $data) );
            return;
        }
        // there was a problem fetching the requested data
        $trans->stop(404, "Resource Not Found");
    }

    public function post($trans) {
        if (!property_exists($trans->request_data, "data")) {
            $trans->stop(400, "Invalid Request", "Missing Request Parameter: data");
        }

        // TODO fix expiry
        $expires = "0000-00-00 00:00:00";

        $stmt = $this->mysqli->prepare(
            'INSERT INTO `sync` (`expires`, `uid`, `data`)
             VALUES (?, ?, ?)'
        );
        $stmt->bind_param("sss", $expires, $trans->request_uid, $trans->request_data->data);

        if ($stmt->execute()) {
            $trans->response_code = 201;
            $trans->response_body = json_encode(
                array("status" => 201, "message" => "Sync Created", "id" => $stmt->insert_id)
            );
            return;
        }
        // something went wrong with the insert
        $trans->stop(500, "Internal Server Error", "Unable to Create Sync");
    }

    public function authorize($trans) {
        // requesting synced keys only requires a valid user, not a valid
        // signature (they don't have the signing key yet)
        if ($trans->request_method == "GET") {
            return parent::authorize($trans, False);
        }
        // posting synced keys requires normal valid signature
        return parent::authorize($trans);
    }
}
?>
