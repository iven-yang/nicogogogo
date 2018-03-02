Overview
========
To start the webserver `go run server.go`
To start the application data server(s) `go run backend.go`

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

Avoiding race conditions 
------------------------
Our application data server operates off of a single file per user object that gets created. Due to this, we do not need to lock the entire database anytime a transaction takes place. Instead, we can lock the user file(s) that will be read and modified in each request handler function. To do this, we created a global map `mutexes` that maps usernames to individual locks. The flow for a typical request to the application data server now looks as follows:

1. The application data server listens for connections.
2. The application data server accepts a connection and starts a goroutine to handle this connection.
3. The created goroutine hits a switch case based on the type of action that will be performed.
4. The goroutine enters the appropriate handler function for the requested action.
5. The handler calls a locking function that tells all other backend servers to acquire the lock and hold it for the file that will be modified.
6. After all other backend servers either timeout during the request or respond that they have acquired the lock, the locking function locks the file for the current backend server. Only one lock can be held by a single handler function per server at any given time to avoid deadlocks.
7. The handler function performs any read and write operations on the locked file.
8. The handler calls an unlocking function that tells all other backend servers that responded during the distributed locking phase (parts 5-6) to release the lock for the file that was modified.
9. After all other backend servers either timeout during the request or respond that they have released the lock, the unlocking function releases the lock and the handler function responds to the connection request that was accepted.
10. Files are synced whenever a file is modified on one backend server (while all the servers have locks on that file)

With this data flow, only one handler function, and thus one goroutine, can operate on a given user file at any point in time. Additionally, handler functions are limited to acquiring only a single lock at any point in their execution to avoid deadlocks that may be caused by context switches. 
