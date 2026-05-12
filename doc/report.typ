#import "@preview/diagraph:0.3.7": raw-render

#set heading(numbering: "1.")
#set text(font: "New Computer Modern", lang: "en", region: "fi")

#align(center)[
  #align(horizon)[
    #title[Exercise Work - Authorization Server]
    Tampere University - COMP.SEC.300 - Secure Programming \
    #link("mailto:leevi.j.koponen@tuni.fi")[Leevi Koponen]
  ]

  #outline()
  #pagebreak()
]

= Summary

This document serves both as somewhat ad hoc design documentation and course
mandated report submission for a loosely OAuth 2.1 @oauth21 based authorization
server. The primary goal is to explore more stringently defining the security
context and risks related to the application to document reasoning that then
allows further review when assumptions or the design changes.

= Architecture

== Usage

At a basic level the user is to be directed to the authorization page, signs in
as necessary and affirms the request to redirected back to the client that began
the flow, where the client will then retrieve the final access token.

#figure(
  raw-render(
    ```dot
    digraph {
      nodesep=0.125

      start [label="Needs authorization", shape=diamond]
      handle [label="Authorization page"]
      login [label="Handle login"]
      authorize [label="User accepts"]
      callback [label="User returned"]
      retrieve [label="Request token"]
      generate [label="Generate token"]
      done [label="Has token", shape=diamond]

      subgraph client {
        label="Registered client"
        cluster=true

        start
        done

        callback -> retrieve
      }

      subgraph preview {
        label="Authorization server"
        cluster=true

        generate

        handle -> login [style="dashed"]
        login -> authorize [style="dashed"]
        handle -> authorize [label="Logged in"]
      }

      start -> handle [label="Browser redirect"]
      authorize -> callback [label="Browser redirect"]
      retrieve -> generate [label="HTTP request"]
      generate -> done [label="HTTP response"]
    }
    ```,
    width: 100%,
  ),
  caption: "Authorization Code Flow",
)

== Implementation

The application consists of a minimal password based login system, utilizing
Argon2 @argon2 for hashing. The identity is stored and validated with a signed
JSON web token @jws, using the HS256 scheme as defined in the corresponding
algorithm definition specification @jwa.

=== Backend

The backend is a minimal Rust API server using a single threaded asynchronous
runtime for accepting requests. The actual cryptographic operations and relevant
parsing as well as an initial SQLite backed storage implementation are done on
separate worker threads.

This approach is based on the assumption that the application logic itself is
unlikely to get particularly large, so using a full work stealing executor for
request handling is overkill over just spreading work through other means.

=== Frontend

The frontend is implemented as a tiny single page application, largely just to
save from the effort of doing HTML templating and dealing with cookie state on
the backend side, as well as more complicated CSRF mitigations required when
using cookies as the authorization method.

= Solutions

== Password Handling

Password storage has been implemented according to the OWASP recommendations
@cheatsheets[Password Storage Cheat Sheet], in summary, the hashing
library in question has been verified to use appropriately high memory and
iteration costs with it's default options.

In addition, extra care has been taken to ensure that the plain text password
is being treated with a secret specific type that guarantees memory being zeroed
and prevents accidental exposure, requiring explcictly requesting access the
value itself.

The flow for invalid usernames includes hashing the password regardless to make
it harder to extract account existence. Ideally a more modern approach like
OPAQUE @opaque would be used to verify passwords, as it has been explicitly
designed to support this case natively, in addition to the server never gaining
the temporary access to the password plaintext.

== Session Management

= Defects

== Specification Compliance

In general, the authorization flow is not particularly compliant, i.e. most
request/response parameters do not entirely match the real format. However, the
surrounding approach is implemented as intended, just ignoring the complexity
around the specified expandability.

== Authorization Scopes

The implementation of authorization scope handling has been left out due to time
pressure. This was done with the understanding that while it's a large part of
the application's usablity, it's not entirely relevant in terms of this course's
scope, given implementation is just about defining a database schema for them
and combining some simple union and intersection set operations.

== Client Registration

Similar to above, the concept of registering client applications that have
access to specified scopes and allow specific redirect URLs is quite core to
the functionality, but has this has been left as a simple globally configured
allow list.

== Token Verification

While the current approach of requiring client applications to verify tokens
against the authorization server is perfectly workable, it's becoming more
common to utilize asymmetric signatures that are published through a JWK @jwk
key set that applications refresh periodically to handle rotation.

== Error Handling

Currently the application does not meaningfully report errors beyond appropriate
HTTP status codes, nor does it have the infrastructure for logging the details.

== Limited Testing

The application has only a minimal amount of testing of the basic usage and
limited sanity checks against potential misuse. This was left bare both for time
reasons and the existence of tooling like OAuch @oauch that could be used to
find issues once the implementation is expanded to be more standard compliant.

= Lessons

== Cheatsheet Quality

The OWASP Cheat Sheet project @cheatsheets is an incredibly high quality
resource that has well explained rationale and actionable guidance for almost
every security critical aspect of a typical application.

Despite this, it seems that older or plain poor tutorials on the internet that
recommend less secure approaches dominate mindshare, as shown with how many
projects both in weekly meetings and even final presentations had clearly not
followed the current recommendations.

== Specification Complexity

Specifications like OAuth @oauth21 are deviliously complex, having been built up
over years of iteration and adding new security features, even with the 2.1
version's draft that I mostly looked at, which has removed some old insecure
approahes and included separate specifications like PKCE into the same document.

= References

#bibliography(
  "sources.bib",
  style: "ieee",
  title: none,
)
