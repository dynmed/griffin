# Griffin #

## Introduction ##
* Centralized storage of passwords and other sensitive data
* Accessible by clients that possess keys and perform all crypto operations client-side

## Design Principles ##
* Distrust the Server: assume the server will be compromised at some point
* Less is More: client and server code should be as simple as possible (complexity == bugs)

## Technical Design ##

### Use Cases ###
* Website passwords
* Credit cards
* Sensitive data (SSN, etc.)

### Key Management ###
* Master Password (MP): known to user only, used to generate Data Encryption Key
* Data Encryption Key (DEK): 256 bit key generated using MP and PBKDF2, used to encrypt all sensitive data
* Request Authentication Key (RAK): 80 bit shared secret between client and server, generated when new client established, used to HMAC requests for data from the server.
Note: 80 bits is the approximate length of 16 monocased alphanumeric characters. This is assumed to be a reasonable amount of data to manually transfer to a new client (4 rows of 4 characters).

### Workflows ###

#### Set Up Server ####
1. Install application files on web server.
2. In configuration files configure database host, credentials, table prefix.
3. Optionally configure admin email contact to validate new accounts. Leaving blank leaves server open to public for signups.
4. At this point an anonymous request to the project root displays the basic info needed to configure new clients.

#### Set Up Client ####
1. Install client application
2. Configure base URL for server
3. Client confirms valid server certificate. Invalid certificate results in a hard failure.
4. Client presents option for new or existing account.
5. If new account:
    1. Client generates new RAK, stores it locally
    2. Prompts user for desired username
    3. Sends request for new account to server
    4. Server validates request:
        1. username available
        2. RAK strong enough
        3. client below request threshold
    5. If request is valid:
        1. server creates account, stores username and RAK
        2. responds with a success message
    6. Otherwise, respond with an error message
6. If existing account:
    1. Client prompts user for username and RAK from existing client (provides information on where to find RAK)
    2. Client confirms correct username and RAK by making an authenticated request to the server and checking for a success response code

#### Store Secure Item ####

1. User enters data to be stored into UI and indicates “Save Data”
2. Client checks if client session is active, i.e. DEK is in memory
3. If no active client session:
    1. Prompt user for master password and generate DEK
    2. Otherwise retrieve DEK from client session
4. Encrypt data with DEK and create payload to send to server for storage
5. Send payload to server and authenticate request with HMAC using RAK

#### Retrieve Secure Item ####
1. User interacts with UI and indicates “Retrieve Data”
2. Based on UI context, client determines which records to request from server
3. Creates payload to send to server to request records
4. Send payload to server and authenticate request with HMAC using RAK
5. Client checks if client session is active, i.e. DEK is in memory
6. If no active client session:
    1. Prompt user for master password and generate DEK
    2. Otherwise retrieve DEK from client session
7. Decrypt records with DEK and update the UI with the 

### Data Model ###
The following schema defines the data types stored by the server:

* TBD

### Server API ###
The server implements a basic REST API.  It supports multiple API versions by exposing a version number as the second chunk of the path.

* `/api/1/data`
    * POST: create a new stored item
* `/api/1/data/{id}`
    * GET: retrieve the stored item with given id
    * PUT: update the stored item with given id
    * DELETE: delete the stored item with given id
* `/api/1/data/search`
    * POST: retrieve the set of stored items that match the query
        * params: query (string)
* `/api/1/auth`
    * PUT: update the current user’s RAK

### Client API ###
The client is responsible for all cryptographic operations other than those performed by the server during request validation.  The following API is optional for clients to implement, but will help organize client application code around the standard workflows.

TODO move the response codes to the Server API, they don’t belong here

* `create_item`: create a new secure item and store it on the server
    * args:
        * type (int): type of record, i.e. website, credit card, data
        * public_name (string): plaintext identifier for the record
        * data (string): plaintext JSON data to store
    * returns:
        * 200: item ID (int) if success
        * 400: error code if failure
* `get_item`: return a secure item from the server
    * args:
        * id (int): item ID for the record
    * returns:
        * 200: item (JSON)
        * 400: error code if failure
* `edit_item`: modify the attributes of a secure item on the server
    * args:
        * id (int): item ID for the record
        * updates (JSON): name-value pairs of fields to modify
    * returns:
        * 200: item ID (int) if success
        * 400: error code if failure
* `delete_item`: delete a secure item from the server
    * args:
        * id (int): item ID of the record to delete
    * returns:
        * item ID if success
        * error code if failure
* `get_items`:  return a list of secure items from the server that match a query string
    * args:
        * query (string): Optional. Query string to match secure items. Empty query returns all items.
    * returns:
        * list of secure items
* `decrypt_data`: decrypt data using DEK and return data in JSON format
    * args:
        * data (string): encrypted JSON data
    * returns:
        * plaintext JSON data (string)
* `encrypt_data`: encrypt data using DEK and return encrypted bytes
    * args:
        * data (string): plaintext JSON data
    * returns:
        * encrypted JSON data (string)
* `get_master_password`: prompt user for MP and return the string entered
    * args:
        * None
    * returns:
        * characters entered (string)
* `get_dek`: generate and return DEK based on MP
    * args:
        * None
    * returns:
        * DEK (string)

## Threat Model ##

* TBD