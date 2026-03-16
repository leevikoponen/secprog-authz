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

= References

#bibliography(
  "sources.bib",
  style: "ieee",
  title: none,
)
