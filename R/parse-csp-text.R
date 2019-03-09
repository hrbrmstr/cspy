#' Does a URL have a content security policy?
#'
#' @param URL URL
#' @param method method to use fetch CSP (sites may change headers returned
#'        depending on the method used)
#' @export
has_csp <- function(URL, method = c("head", "get")) {

  method <- match.arg(tolower(method), c("head", "get"))

  r <- if (method == "head") httr::HEAD(URL) else httr::GET(URL)

  httr::warn_for_status(r)

  h <- httr::headers(r)

  csp <- h[["content-security-policy"]]

  length(csp) != 0

}

#' Fetch and/or parse a content security policy header value
#'
#' Use [fetch_csp()] to load & parse a CSP from a remote site. Use [parse_csp()]
#' to parse an already fetched or composed CSP.
#'
#' @param csp_text length 1 character vector containing CSP text
#' @param origin_url site to fetch CSP from or to use when just parsing a
#'        plain text (possibly already fetched) CSP
#' @param method method to use fetch CSP (sites may change headers returned
#'        depending on the method used)
#' @references [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
#' @export
parse_csp <- function(csp_text, origin_url) {

  ParserWithLocation <- J("com.shapesecurity.salvation.ParserWithLocation")

  list(
    policy = ParserWithLocation$parse(csp_text, origin_url),
    origin = origin_url
  ) -> p


  class(p) <- c("csp")

  p

}

#' @rdname parse_csp
#' @export
fetch_csp <- function(origin_url, method = c("head", "get")) {

  method <- match.arg(tolower(method), c("head", "get"))

  r <- if (method == "head") httr::HEAD(origin_url) else httr::GET(origin_url)

  httr::warn_for_status(r)

  h <- httr::headers(r)

  csp <- h[["content-security-policy"]]

  if (length(csp) == 0) {
    stop("Content-Security-Policy header not found at ", origin_url, call.=FALSE)
  }

  p <- parse_csp(csp, origin_url)

  p[["origin"]] <- origin_url

  p

}

#' Printer for CSP objects
#'
#' @keywords internal
#' @param x CSP object
#' @param ... unused
#' @export
print.csp <- function(x, ...) {
  cat(gsub(";[[:space:]]*", "\n", x$policy$show()))
}


# #' Update an origin in a `csp` object
# #'
# #' @param csp a `csp` object created with [fetch_csp()] or [parse_csp()]
# #' @param origin_url origin URL
# #' @return `csp` object
# #' @export
# set_origin <- function(csp, origin_url) {
#
#   csp[["origin"]] <- origin_url
#
#   csp
#
# }

