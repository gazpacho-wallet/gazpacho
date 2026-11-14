# llhttp, vendored for the local API server

| | |
|---|---|
| What | The generated C parser of llhttp: `include/llhttp.h`, `src/api.c`, `src/http.c`, `src/llhttp.c`, and its `LICENSE-MIT` |
| Release | v9.4.3, tag `release/v9.4.3` of github.com/nodejs/llhttp, published 2026-07-30 |
| Tag commit | `0e815792b167a9bd8ace259b95b7da953776c288` |
| Release archive | `https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.3.tar.gz`, SHA-256 `1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39` |
| Licence | MIT (`LICENSE-MIT`) |
| Changes | None. The files are byte for byte the archive's; `SHA256SUMS` pins each, and `tools/check-llhttp.sh` (CTest `api_llhttp_pinned`) fails the build on any difference or any extra file |
| Build | Compiled as its own static library, `gazpacho_llhttp`, with the compiler's default warnings and no `-Werror` (its warnings are upstream's) |
| Used in | `ports/api/http.c` only, in its default strict mode: no `llhttp_set_lenient_*` call is made |

## Why llhttp, not picohttpparser

`spec/local-api.md` 3.1 asks for "an HTTP/1.1 parser with a published fuzzing
record (for example one fuzzed continuously in OSS-Fuzz), not one written for
this program". Both candidates are MIT-licensed C used in large servers.

- **Fuzzing record.** llhttp has its own OSS-Fuzz project (`projects/llhttp`),
  run continuously against the parser itself. picohttpparser is fuzzed as part
  of H2O's OSS-Fuzz project, through H2O's HTTP/1 driver, not as a project of
  its own.
- **Exposure.** llhttp parses every HTTP/1 request Node.js serves. Its
  request-smuggling history (lenient parsing of `Transfer-Encoding`,
  `Content-Length`, obsolete line folding, bare CR or LF) was fixed by making
  strict parsing the default, with each leniency an explicit opt-in. The
  server uses none of them.
- **What strict mode refuses for us.** `Content-Length` together with
  `Transfer-Encoding`, duplicate or malformed `Content-Length`, obsolete line
  folding, invalid header characters, bare CR or LF line endings, and invalid
  methods and versions are refused by the parser itself; the server refuses
  the rest of 3.1 on top (chunked request bodies, upgrades, sizes, HTTP
  versions other than 1.1).
- **Callbacks with pause.** llhttp can pause at the end of the head and at the
  end of each message, so every check of section 5 runs before a byte of the
  body is read and before a pipelined request is looked at.
- **Against it.** llhttp is generated code (llparse), about 10,000 lines, so it
  is not reviewed line by line here; picohttpparser is about 700 hand-written
  lines that could be. picohttpparser also accepts obsolete line folding (it
  reports continuation lines to the caller) and leaves `Content-Length` and
  `Transfer-Encoding` entirely to the caller, which would mean writing the
  smuggling checks ourselves. With llhttp the parser enforces them and our own
  fuzz target (`tests/api/fuzz_api_http.c`) covers the glue and every check
  after it.

## Updating

Download the new release archive, check its SHA-256 against the release, copy
the five files above unchanged, regenerate `SHA256SUMS` with
`sha256sum include/llhttp.h src/api.c src/http.c src/llhttp.c LICENSE-MIT`,
update this table, and run the API tests and the fuzz targets.
