% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/as-data-frame.R
\name{as.data.frame.csp}
\alias{as.data.frame.csp}
\title{Convert a parsed CSP into a data frame of directives and values}
\usage{
\method{as.data.frame}{csp}(x, row.names = NULL, optional = NULL,
  include_origin = TRUE, ...)
}
\arguments{
\item{x}{a \code{csp} object created with \code{\link[=fetch_csp]{fetch_csp()}} or \code{\link[=parse_csp]{parse_csp()}}}

\item{row.names, optional, ...}{ignored}

\item{include_origin}{if the \code{csp} object has an origin URL should
it be included in the data frame? Default: \code{TRUE}}
}
\description{
Convert a parsed CSP into a data frame of directives and values
}
\references{
\href{https://www.w3.org/TR/CSP3/}{Content Security Policy Level 3}
}
