# End-to-End Encrypted File Sharing System
The client will allow users to store and load files,
share files with other users, and revoke access to a shared file from other users.

Users of the application will launch the client and provide their username and password. Once
authenticated, they will use your client to upload and download files to/from the server. The client
will be the interface through which users can interact with the files stored on the server.

Uses two servers:

• The first server, Keystore, provides a public key store for everyone. It is trusted.

• The second server, Datastore, provides key-value storage for everyone. It is untrusted.

Client is stateless and ensures confidentiality and integrity of files in addition to the basic file-sharing
functionality.

Documentation on the planning and design are in the included PDFs.