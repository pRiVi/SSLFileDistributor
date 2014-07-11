This software implements a HTTPS server with browser based client certfication generation.

After this you can create a directory tree per certificate id and allow the client to browse it and download files.

For the HTTPS server you can use normal webserver certificates from startssl(for free!) or any other certificate provider. The client certicates can be issued by an own certification authority, which you can create with the included mkca-dist Toolset. Via this way the browser of the clients brings no warnings (server authentication is normal) and the client certificates can be verified by your server, too. Your client certificates can be used for any domain you want, they must only be create one time to can be used on any host you want to without having the user to create new ones.

Supports firefox, chrome, internet explorer, and so on.

Simple and awesome!

