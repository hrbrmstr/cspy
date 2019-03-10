#' Valid CSP Directives
#'
#' A character vector of valid CSP directives as per
#' Content Security Policy Level 3 W3C Working Draft, 15 October 2018
#' (<https://www.w3.org/TR/CSP3/#iana-registry>).
#'
#' @docType data
#' @keywords datasets
#' @export
c(
  "base-uri", "block-all-mixed-content", "child-src", "connect-src",
  "default-src", "font-src", "form-action", "frame-ancestors", "frame-src",
  "img-src", "manifest-src", "media-src", "object-src", "prefetch-src",
  "plugin-types", "report-uri", "report-to", "require-sri-for", "sandbox",
  "script-src", "script-src-attr", "script-src-elem", "style-src",
  "style-src-attr", "style-src-elem", "upgrade-insecure-requests", "worker-src"
) -> valid_csp_directives