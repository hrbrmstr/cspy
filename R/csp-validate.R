#' Validate a CSP
#'
#' Validates a content security policy. If policy problems are found
#' a data frame of information notes, warnings and errors is returned
#' with the specific locations of the issues in the original CSP string.
#'
#' @param csp a `csp` object created with [fetch_csp()] or [parse_csp()]
#' @return data frame
#' @export
validate_csp <- function(csp) {

  Notice <- J("com.shapesecurity.salvation.data.Notice")

  app <- J("is.rud.crsspy.App")

  p <- csp[["policy"]]

  x <- app$get_notices(p$show(), csp[["origin"]])

  errs <- Notice$getAllErrors(x)
  info <- Notice$getAllInfos(x)
  warn <- Notice$getAllWarnings(x)

  e <- errs$toArray()
  do.call(
    rbind.data.frame,
    lapply(e, function(.x) {
      data.frame(
        message = .x$message,
        type = .x$type$toString(),
        start_line = .x$startLocation$line,
        start_column = .x$startLocation$column,
        start_offset = .x$startLocation$offset,
        end_line = .x$endLocation$line,
        end_column = .x$endLocation$column,
        end_offset = .x$endLocation$offset,
        stringsAsFactors = FALSE
      )
    })
  ) -> edf

  i <- info$toArray()
  do.call(
    rbind.data.frame,
    lapply(i, function(.x) {
      data.frame(
        message = .x$message,
        type = .x$type$toString(),
        start_line = .x$startLocation$line,
        start_column = .x$startLocation$column,
        start_offset = .x$startLocation$offset,
        end_line = .x$endLocation$line,
        end_column = .x$endLocation$column,
        end_offset = .x$endLocation$offset,
        stringsAsFactors = FALSE
      )
    })
  ) -> idf

  w <- warn$toArray()
  do.call(
    rbind.data.frame,
    lapply(w, function(.x) {
      data.frame(
        message = .x$message,
        type = .x$type$toString(),
        start_line = .x$startLocation$line,
        start_column = .x$startLocation$column,
        start_offset = .x$startLocation$offset,
        end_line = .x$endLocation$line,
        end_column = .x$endLocation$column,
        end_offset = .x$endLocation$offset,
        stringsAsFactors = FALSE
      )
    })
  ) -> wdf

  out <- do.call(rbind.data.frame, list(edf, wdf, idf))

  class(out) <- c("tbl_df", "tbl", "data.frame")

  out

}
