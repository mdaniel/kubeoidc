# kubeoidc

![](https://github.com/mdaniel/kubeoidc/workflows/Go/badge.svg)

kubeoidc works as OpenID Connect client for kubectl.
 
The binary has been updated to add special casing for interactions with Google Suite,
in order to successfully create a refresh token when the issuer is `https://accounts.google.com`.
Previously the inclusion of the `group` scope was excluded for that magic issuer,
but now there is a `-scopes` argument and one may include or exclude scopes at will.

It has also been expanded to include more configuration parameters,
to allow one to use the binary with more redirect-uri values, without recompilation.

## Installation

Please download built binaries from the
[latest successful workflows](https://github.com/mdaniel/kubeoidc/actions?query=workflow%3AGo+is%3Asuccess)

Or you can build it yourself:

```console
$ git clone https://github.com/mdaniel/kubeoidc.git
$ cd kubeoidc
$ go build ./...
$ ./kubeoidc -h
```

## Usage

1. Run `kubeoidc -issuer=https://your-dex.example.com -client-id=oidc-client-id -client-secret=oidc-client-secret`
1. The login page provided by OIDC issuer will be shown in a web browser.

   By default it will use an available local port, but you can customize that
   behavior via the `kubectl -callback-port=3000` and the same with the URI and hostname

1. After logging in, kubeoidc shows you a configuration snippet for kubectl,
   or you can have `kubeoidc` automatically add the credential by specifying
   
   `kubeoidc -set-credential=the-kubeconfig-name -client-id=etc etc`
