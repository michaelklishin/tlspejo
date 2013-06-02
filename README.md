# What is TLSpejo

TLSpejo is a tiny TLS echo server that can be used for basic TLS client testing.
It does what `openssl s_server` does, trading the endless number of features
`s_server` provides for extensibility and hackability of a tiny program.

DatTrack was developed to aid TLS client development and as a small
code kata excercise and should not be taken seriously.


## Supported TLS Versions

Only TLSv1 is supported.


## Building

    go build .


## Usage

    tlspejo [--key-file ... --cert-file ...]


## License

Released under the BSD license.

Copyright Michael S. Klishin, 2013
