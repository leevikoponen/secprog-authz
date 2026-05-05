#import "@preview/diagraph:0.3.7": raw-render

#set page(paper: "presentation-16-9")
#set text(font: "New Computer Modern", size: 18pt, lang: "en", region: "fi")

#let slide(name, content) = [
  #pagebreak()
  = $name$
  #v(2em)
  $content$
]

#align(center + horizon)[
  #title[Authorization Server]
  #link("mailto:leevi.j.koponen@tuni.fi")[Leevi Koponen]
]

#slide("Project Summary")[
  - Loosely OAuth 2.1 inspired identity/authorization server
    - The underlying standard of most modern sign in flows you see everywhere
    - OpenID Connect specifies more on top and adds some alternative approaches

  - Generally quite more stripped down implementation than planned
    - Personal reasons limited available time
    - Pivoted towards rough infrastructure and rationalizing in report
]

#slide("Technical Choices")[
  - Rust backend on top of barebones HTTP library (Hyper)
    - Functionality generally built with only basic primitives
    - High quality basic cryptography libraries readily available
    - SQLite kept on a separate worker thread for persistence

  - Minimal SPA frontend built with Preact
    - Ultimately not any easier to deal with than just plain SSR and forms
    - Originates from idea about implementing more complex password proof flow
]

#slide("Authorization Flow", columns(2)[
  + Client application generates and stores state for the exchange
  + Client forms redirection URL and transfers user to provider
  + User signs in as necessary (session reuse)
  + User authorizes what information to provide back
  + User redirected back to application with short lived exchange code
  + Client application requests token and gets authorization claims

  #raw-render(```dot
    digraph flow {
      initiate [label="Client initiates process (1-2)"]
      authorize [label="User confirms request (3-4)"]
      exchange [label="Client gains access (5-6)"]

      initiate -> authorize [label="Redirect to provider"]
      authorize -> exchange [label="Redirect to application"]
    }
  ```)
])

#slide("Flow Details")[
  - State gets passed as query parameters within redirects

  - Having a random exchange identifier effectively functions as a CSRF token
  - PKCE handles against interception attacks
    - Client stores random value and passes hash when initiating flow
    - Server requires the original value in order to give access token

  - Concept of authorization scopes allows for privilege restrictions
    - Sensitive scopes can limit themselves to being highly temporary
    - Selectively allow silently gaining some to reduce friction
]

#slide("Password Handling")[
  - Passwords hashed with Argon2(id)
    - Current recommendation in OWASP Password Storage Cheat Sheet
    - In memory storage through wrapper type that zeroes memory on drop

  - Considered switching to using OPAQUE instead
    - Server never gains even temporary access to password
    - Primarily meant for using password both for access control and encryption
      - Planned library was audited for it's use in WhatsApp E2EE backups
]

#slide("Session Management")[
  - Authorization tokens are HS256 JWTs
    - Very cheap to verify without hitting database
    - Intended be short lived to avoid revocation complexity
      - Applications can transparently refresh as needed
    - Secrets stored in database and rotated periodically

  - Refresh tokens and sessions backed by IDs
    - Allows for user to explicitly revoke when required
    - Sort of achievable with JWTs using key IDs and revocation lists
      - Still needs a database access so rarely meaningfully preferable
]

#slide("Testing Approach")[
  - End to end tests with a headless browser through Playwright
  - Some unit tests largely for ensuring that cryptography works
    - Ideally would have some more considering relatively custom implementations

  - Mostly manually reviewing chosen approaches against OWASP recommendations
    - Hoping I'll find time to document this more comprehensively
]

#slide("Implementation Defects")[
  - I've left out the concept of clients and generic scope handling
    - Reliant on static configuration of allowed redirects
    - Lack of email leads to not having recovery options either

  - SBOM creation and automated scanning
    - Lack of tooling that also provides good experience when ran locally
      - Relying on vendor locked CI isn't ideal, especially for small projects

  - Any kind of nice look and feel, so not much to showcase
    - Just typical login form and checkboxes and a button after that
]

#slide("Lessons Learned")[
  - OWASP Cheatsheets are really good at describing what you should be doing
    - Most include clear rationale with good references

  - OAuth comprises of a few simple enough parts
    - But tons of work to write and plug everything together
      - Has evolved over time to expand security features
    - Didn't really help that I was already largely knowledgeable about basics
]
