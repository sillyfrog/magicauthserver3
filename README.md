# Magic Auth Server

A sample authentication server to work with my [Magic Reverse Proxy](https://github.com/sillyfrog/magicreverseproxy), including support for two factor auth with [Authy](https://authy.com/)

A `Dockerfile` is included, this pulls in all of the dependancies via pip.

Initially, you will need to add some usernames and passwords, this is done by running it with `-a`, eg:
```
$ ./authserver -a
Username: someone
Password:
```
If running in docker, you can run
```
docker run -ti -v <full path>/proxylogins:/proxylogins localhost:5000/authserver3:latest ./authserver.py -a
```

This will create or append to the `proxylogins` file. This is has a username and password (hashed) per line. When running in production, `proxylogins` can be configured as read-only.

A `otpkeys` file should also be connected to the docker container, as read-write, this is where the keys/hashes for each user are stored.

The first time a user goes to login, they must configure the OTP in Authy (or similar app) and login. Once this is done, the key/hash is saved. The user will be displayed a QR code to scan with their phone.

Once at least one user account (username and password) has been created, you can run the auth server. The domain for cookies that are set must be configured. The idea is that the cookie is set on your root domain, so the authentication flows to all other subdomains, for example if you run:
```
./authserver -d example.com
```

Then you could have a number of subdomains, such that when you authenticate with 1 domain, you are authenticated with them all, eg:
 - index.example.com
 - first.example.com
 - more.example.com

## authform.html

The included `authform.html` in the templates directory is a simple username and password from, that sends the auth details back using AJAX. The implementation is this way because of how nginx does it proxying/caching with the auth server. Using a traditional POST caused all sorts of weird reliability issues (this could have been anything from Docker buffer sizes to shell buffers to something else). This method worked well for me, so it stayed.

That said, the HTML/CSS of the from can be totally customised as you require.

## Docker

If running in docker, build the image first:
```
docker build . -t authserver
```

Then run it with something like (note the `templates` is optional):
```
docker run --name authserver -d -p 80:80 -e "DOMAIN=example.com" -v /etc/localtime:/etc/localtime:ro -v /path/to/proxylogins:/proxylogins:ro -v /path/to/otpkeys:/otpkeys -v /path/to/templates:/templates
```



