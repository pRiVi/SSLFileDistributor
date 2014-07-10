This software implements a HTTPS server and allows the user to create client certificates for the browser in the browser.

After this you can create a directory tree per certificate id and allow the client to browse it and download files.

For the HTTPS server you can use normal webserver certificates from startssl(for free!) or any other certificate provider. The client certicates cat be issued by an own certivication authority, which you can create with the also included mkca-dist Toolset. Via this the browser of the clients brings no warnings (server authentication is normal) and the client certificates can be verified by your server, too. Your client certificates can be used for any domain you want, they must only be create one time to can be used on any host you want to without having the user to create new ones.
