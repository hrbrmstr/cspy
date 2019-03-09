#' Convert a parsed CSP into a data frame of directives and values
#'
#' @param x a `csp` object created with [fetch_csp()] or [parse_csp()]
#' @param include_origin if the `csp` object has an origin URL should
#'        it be included in the data frame? Default: `TRUE`
#' @param row.names,optional,... ignored
#' @references [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
#' @export
as.data.frame.csp <- function(x, row.names=NULL, optional=NULL, include_origin = TRUE, ...) {

  p <- x$policy
  d <- p$getDirectives()

  do.call(
    rbind.data.frame,
    lapply(d$toArray(), function(.x) {
      vals <- .x$values()$toArray()
      if (length(vals)) {
        vals <- sapply(vals, function(.y) .y$show())
      } else {
        vals <- "'none'"
      }
      data.frame(
        directive = .x$name,
        value = vals,
        stringsAsFactors = FALSE
      )
    })
  ) -> xdf

  if (nrow(xdf) > 0) {
    if ((!is.na(x$origin)) && include_origin) xdf[["origin"]] <- x$origin
  }

  class(xdf) <- c("tbl_df", "tbl", "data.frame")

  xdf

}
