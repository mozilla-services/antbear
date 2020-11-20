# * [ ] Must have a CSP with
#   * [ ] a report-uri pointing to the service's own `/__cspreport__` endpoint
#   * [ ] web API responses should return `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; report-uri /__cspreport__` to disallowing all content rendering, framing, and report violations
#   * [ ] if default-src is not `none`, frame-src, and object-src should be `none` or only allow specific origins
#   * [ ] no use of unsafe-inline or unsafe-eval in script-src, style-src, and img-src
