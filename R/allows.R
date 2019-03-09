#' Tests for what a parsed CSP allows
#'
#' @name csp_allows
NULL

#' @param csp a `csp` object created with [fetch_csp()] or [parse_csp()]
#' @param URL source or destination URL
#' @param nonce a [cryptographic nonce](https://html.spec.whatwg.org/multipage/urls-and-fetching.html#attr-nonce)
#' @rdname csp_allows
#' @return logical
#' @references [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
#' @export
allows_child_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsChildFromSource(URL)
}

#' @rdname csp_allows
#' @export
allows_connect_to <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsConnectTo()
}

#' @rdname csp_allows
#' @export
allows_font_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsFontFromSource()
}

#' @rdname csp_allows
#' @export
allows_form_action <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsFormAction()
}

#' @rdname csp_allows
#' @export
allows_frame_ancestor <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsFrameAncestor()
}

#' @rdname csp_allows
#' @export
allows_frame_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsFrameFromSource()
}

allows_img_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsImgFromSource()
}

#' @rdname csp_allows
#' @export
allows_manifest_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsManifestFromSource()
}

#' @rdname csp_allows
#' @export
allows_media_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsMediaFromSource()
}

#' @rdname csp_allows
#' @export
allows_navigation <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsNavigation()
}

#' @rdname csp_allows
#' @export
allows_object_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsObjectFromSource()
}

# #' @rdname csp_allows
# #' @export
# allows_plugin <- function(csp) {
#   allowsPlugin()
# }

#' @rdname csp_allows
#' @export
allows_prefetch_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsPrefetchFromSource()
}

#' @rdname csp_allows
#' @export
allows_script_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsScriptFromSource()
}

# #' @rdname csp_allows
# #' @export
# allows_script_with_hash <- function(csp) {
#   allowsScriptWithHash()
# }

#' @rdname csp_allows
#' @export
allows_script_with_nonce <- function(csp, nonce) {
  csp[["policy"]]$allowsScriptWithNonce(nonce)
}

#' @rdname csp_allows
#' @export
allows_style_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsStyleFromSource()
}

# #' @rdname csp_allows
# #' @export
# allows_style_with_hash <- function(csp) {
#   allowsStyleWithHash()
# }

#' @rdname csp_allows
#' @export
allows_style_with_nonce <- function(csp, nonce) {
  csp[["policy"]]$allowsStyleWithNonce(nonce)
}

#' @rdname csp_allows
#' @export
allows_unsafe_inline_script <- function(csp) {
  csp[["policy"]]$allowsUnsafeInlineScript()
}

#' @rdname csp_allows
#' @export
allows_unsafe_inline_style <- function(csp) {
  csp[["policy"]]$allowsUnsafeInlineStyle()
}

#' @rdname csp_allows
#' @export
allows_worker_from_source <- function(csp, URL) {
  URL <- J("com.shapesecurity.salvation.data.URI")$parse(URL)
  csp[["policy"]]$allowsWorkerFromSource()
}

# allows_attribute_with_hash <- function(csp) {
#   allowsAttributeWithHash()
# }
