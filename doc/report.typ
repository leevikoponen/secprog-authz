#import "@preview/diagraph:0.3.6": raw-render

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

Note that this section is currently more of a plan than an accurate description.

== Flow

At a basic level the user is to be directed to the authorization page, signs in
as necessary and affirms the request to redirected back to the client that began
the flow, the client will then retrieve the final access token.

#figure(
  raw-render(
    ```dot
    digraph flow {
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

This core will then serve as a base for handling the authorization flow itself,
based on further configuration.

=== Backend

The backend is a minimal Rust API server using a single threaded asynchronous
runtime for accepting requests. The actual cryptographic operations and relevant
parsing as well as an initial SQLite backed storage implementation are done on
separate worker threads.

This approach is based on the assumption that the application logic itself is
unlikely to get particularly large, so using a full work stealing executor for
request handling is overkill over just spreading work through other means.

=== Frontend

The frontend is implemented as a tiny vanilla single page application, largely
just to save from the effort of doing HTML templating and dealing with cookie
state on the backend side.

#pagebreak()

= References

#bibliography(
  "sources.bib",
  style: "ieee",
  title: none,
)
