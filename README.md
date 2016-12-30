# Tunneled Server

The Tunneled Server is what powers http://tunneled.computer. It allows you to
create a tunnel between your local computer and a subdomain of your choice at
tunneled.computer. Think [ngrok](http://ngrok.io).

This repository is still under heavy development, but if you'd like to test out
the server, feel free to submit a pull request to modify the `users.json` file
with the appropriate information. Ping @bswinnerton for review. Once merged,
you'll be able to open up a new tunnel with this basic SSH command:

```
$ ssh -p 2222 -nNT -R 80:localhost:8000 brooks@tunneled.computer
```

Where `8000` is the local port the service you'd like to expose is running on,
and `brooks` is the username you specified in the `users.json` file.
