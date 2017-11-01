Project Part 2
==============
To start the webserver `go run server.go`
To start the application data server `go run backend.go`

Messages Sent between web server and application data server
-------------------------------------------------------------

Every request made to the web server that requires a query to the application data server, will consist of two parts: a query from the web server to the application data server, and a response from the data server to the web server with the relevant information required to complete the request. Both parts of this transaction consist of a common.Request struct that we created which consists of a SessionID (the requesting user's session ID cookie value), an action (an integer that corresponds to a particular handler to run for the given query), and a data field (map[string]interface{} to allow flexibility in the data that can be sent through this struct). These common.Request structs are encoded and decoded with gob, which also handles the writing and reading to the socket connecting the web server and application data server. To help clarify how one of these transactions takes place, here is a concrete example for a user trying to login:

1. The user POSTs form with `Username: asdf,  Password: test` to webserver's /login route
2. The webserver enter the login handler, recognizes that the user has made a POST request, and formulates a query for the application data server.
3. The webserver creates a common.Request struct, with `SessionID: ""`, `Action: common.LOGIN`, and `Data: {"Method": "POST", "Username": "asdf", "Password": "test"}`.
4. The webserver calls `QueryBackend` with the common.Request struct just created as the argument.
5. `QueryBackend` dials the application data server, gob encodes the common.Request struct passed to it as an argument, and sends the encoded struct to the application data server. It then waits for a reply from the application data server.
6. In its main loop, the application data server accepts the connection from the webserver and receives the gob encoded common.Request struct. The struct is gob decoded, and a switch statement is hit based on the action defined in the `Action` field in the common.Request struct. In this case, the `Action` field is set to common.LOGIN, so the `loginHandler` function is called. 
7. The handler function does any necessary operations, then returns a common.Request object to respond to the webserver with. In this case, the loginHandler takes the common.Request struct that was passed to it, goes through the process of authenticating the user (loading relevant file from data store, ensuring hashes match), and then creates a new common.Request struct to return for the main loop to respond to the webserver with. For this example, the common.Request struct would hold the following fields: `SessionID: Newly Assigned SessionID`. `Action: common.RESPONSE`, `Data: {"LoggedIn": true}`
8. This new common.Request gets returned to the main loop and the main loop gob encodes and sends the struct back to the webserver which has been awaiting a response.
9. The webserver receives and gob decodes the response struct. Any further necessary operations are performed based on the data provided in the response struct (e.g. redirecting the user, setting cookies, etc.).

The structure of the files that the application data server will use
---------------------------------------------------------------------
Data is stored in the `db/users` directory. Each user gets its own json file. Whenever an update is required for a user, that user's json file gets updated accordingly.

Modifications to the user interface from the first part
-------------------------------------------------------
Added missing components (profile for easiness to view a specific user's messages, ability to delete account, enforcing of 100 character message limit)
