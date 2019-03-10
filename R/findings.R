mk_finding <- function(category, message, severity, where) {
  data.frame(
    category = category,
    severity = severity,
    message = message,
    where = I(where),
    stringsAsFactors = FALSE
  ) -> out
  class(out) <- c("csp_finding", "tbl_df", "tbl", "data.frame")
  out
}

#' Tests for insecure CSP settings
#'
#' @name csp_security_checkers
NULL

ensure_csp_df <- function(csp_df) {
  if (inherits(csp_df, "csp")) {
    as.data.frame(csp_df)
  } else {
    if (!((is.data.frame(csp_df)) &&
          all(c("directive", "value") %in% colnames(csp_df)))) {
      stop("Value is not a Content Security Policy object or CSP data frame.", call.=FALSE)
    }
    csp_df
  }
}

# Checks if passed csp allows inline scripts.

#' @rdname csp_security_checkers
#' @param csp_df Preferably a CSP data frame (made with [as.data.frame()]) but
#'        can be a raw CSP object. Passing in a pre-made data frame will be faster
#'        when using multiple CSP security checker functions.
#' @return a `csp_finding` or `csp_findings_list` object containing one or more `csp_finding`
#'         objects. Each `csp_finding` object will have the `category`, `severity`,
#'         `message` and `where` the violation(s) occurred.
#' @references [CSP With Google](https://csp.withgoogle.com/docs/index.html)
#' @export
check_script_unsafe_inline <- function(csp_df) {
  csp_df <- ensure_csp_df(csp_df)
  script_src <- csp_df[csp_df[["directive"]] == "script-src",]
  if (nrow(script_src)) {
    unsafe_inline <- script_src[(script_src[["value"]] == "'unsafe-inline'"),]
    if (nrow(unsafe_inline)) {
      return(
        mk_finding(
          category = "script-unsafe-inline",
          severity = "HIGH",
          message = "'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers.",
          where = unsafe_inline
        )
      )
    }
  }
}

# Checks if passed csp allows unsafe eval
#' @rdname csp_security_checkers
#' @export
check_script_unsafe_eval <- function(csp_df) {
  csp_df <- ensure_csp_df(csp_df)
  script_src <- csp_df[csp_df[["directive"]] == "script-src",]
  if (nrow(script_src)) {
    unsafe_eval <- script_src[(script_src[["value"]] == "'unsafe-eval'"),]
    if (nrow(unsafe_eval)) {
      return(
        mk_finding(
          category = "script-unsafe-eval",
          severity = "HIGH",
          message = "'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().",
          where = unsafe_eval
        )
      )
    }
  }
}

URL_SCHEMES_CAUSING_XSS <- c("data:", "http:", "https:")
XSS_DIRECTIVES <- c("script-src", "object-src", "base-uri")

# Checks if plain URL schemes (e.g. http:) are allowed in sensitive directives.
#' @rdname csp_security_checkers
#' @export
check_plain_url_schemes <- function(csp_df) {
  csp_df <- ensure_csp_df(csp_df)
  srcs <- csp_df[csp_df[["directive"]] %in% XSS_DIRECTIVES,]
  if (nrow(srcs)) {
    url_schemes <- srcs[(srcs[["value"]] %in% URL_SCHEMES_CAUSING_XSS),]
    if (nrow(url_schemes)) {
      mk_finding(
        category = "unsafe-execution",
        severity = "HIGH",
        message = "URI(s) found that allow the exeution of unsafe scripts.",
        where = url_schemes
      )
    }
  }
}

# Checks if csp contains wildcards in sensitive directives.
#' @rdname csp_security_checkers
#' @export
check_wildcards <- function(csp_df) {
  csp_df <- ensure_csp_df(csp_df)
  srcs <- csp_df[csp_df[["directive"]] %in% XSS_DIRECTIVES,]
  if (nrow(srcs)) {
    wildcards <- srcs[(srcs[["value"]] == "*"),]
    if (nrow(wildcards)) {
      mk_finding(
        category = "plain-wildcard",
        severity = "HIGH",
        message = "Directives should not allow '*' as source.",
        where = wildcards
      )
    }
  }
}

# Checks if all necessary directives for preventing XSS are set.
#' @rdname csp_security_checkers
#' @export
check_missing_directives <- function(csp_df) {

  findings <- list()

  csp_df <- ensure_csp_df(csp_df)

  # fallback
  default_src <- csp_df[csp_df[["directive"]] == "default-src",]
  has_def_src <- nrow(default_src) > 0

  # check for object-src 'none'
  object_src_missing <- FALSE
  object_src_not_none <- TRUE
  object_src <- csp_df[csp_df[["directive"]] == "object-src",]
  none <- data.frame()
  if (nrow(object_src)) {
    none <- object_src[object_src[["value"]] == "'none'",]
    if ((nrow(none) == 0) && has_def_src) {
      none <- default_src[default_src[["value"]] == "'none'",]
    } else {
      object_src_not_none <- FALSE
    }
  } else if (has_def_src) {
    none <- default_src[default_src[["value"]] == "'none'",]
    object_src_not_none <- FALSE
    object_src_missing <- (nrow(none) == 0)
  }

  if (object_src_not_none) {
    if (nrow(object_src) == 0) object_src <- data.frame(directive = "object-src", value = NA_character_)
    findings[[length(findings)+1]] <- mk_finding(
      category = "weak-directive",
      severity = "POSSIBLY-HIGH",
      message = "Can you restrict object-src to 'none'?",
      where = object_src
    )
  }

  if (object_src_missing) {
    findings[[length(findings)+1]] <- mk_finding(
      category = "missing-directive",
      severity = "HIGH",
      message = paste0(c(
        "Missing object-src allows the injection of plugins",
        "which can execute JavaScript. Can you set it to 'none'?"
      ), collapse = " "),
      where = data.frame(directive = "object-src", value = NA_character_)
    )
  }

  base_uri_missing <- FALSE
  base_uri <- csp_df[csp_df[["directive"]] == "base-uri",]
  if (nrow(base_uri)) {
    none <- base_uri[base_uri[["value"]] == "'none'",]
    if (nrow(none) == 0) {
      self <- base_uri[base_uri[["value"]] == "'self'",]
      if (nrow(self) == 0) base_uri_missing <- TRUE
    }
  } else {
    base_uri_missing <- TRUE
  }

  if (base_uri_missing) {
    findings[[length(findings)+1]] <- mk_finding(
      category = "missing-directive",
      severity = "HIGH",
      message = paste0(c(
        "Missing base-uri allows the injection of base tags.",
        "They can be used to set the base URL for all relative (script)",
        "URLs to an attacker controlled domain.",
        "Can you set it to 'none' or 'self'?"
      ), collapse = " "),
      where = data.frame(directive = "base-uri", value = NA_character_)
    )
  }


  script_src <- csp_df[csp_df[["directive"]] == "script-src",]
  script_src_missing <-  (nrow(script_src) == 0)

  if (script_src_missing) {
    findings[[length(findings)+1]] <- mk_finding(
      category = "missing-directive",
      severity = "HIGH",
      message = "Directive is missing.",
      where = data.frame(directive = "script-src", value = NA_character_)
    )
  }

  if (length(findings)) {
    class(findings) <- c("csp_finding_list")
    findings
  } else {
    invisible(NULL)
  }

}

#' @rdname csp_security_checkers
#' @export
check_ip_source <- function(csp_df) {

  csp_df <- ensure_csp_df(csp_df)

  findings <- list()

  ip_src <- csp_df[grepl("://", csp_df[["value"]]),]
  ip_src[["hostname"]] <- sapply(ip_src[["value"]], function(.x) {
    httr::parse_url(.x)$hostname
  }, USE.NAMES = FALSE)
  ip_src <- ip_src[grepl("^[[:digit:]\\.]+$|:", ip_src[["hostname"]]),]
  if (nrow(ip_src)) {

    # localhost first
    localhost <- ip_src[ip_src[["hostname"]] == "127.0.0.1",]
    if (nrow(localhost)) {
      localhost[["hostname"]] <- NULL
      findings[[length(findings)+1]] <- mk_finding(
        category = "localhost-src",
        severity = "WARN",
        message = "Localhost found as a source URI. Remove this in production environments.",
        where = localhost
      )
    }

    other <- ip_src[ip_src[["hostname"]] != "127.0.0.1",]
    findings[[length(findings)+1]] <- mk_finding(
      category = "ip-src",
      severity = "WARN",
      message = "IP address(es) found as source. Most browsers will ignore this.",
      where = other
    )

  }

  if (length(findings)) {
    class(findings) <- c("csp_finding_list")
    findings
  } else {
    invisible(NULL)
  }

}

DEPRECATED_DIRECTIVES <- c("report-uri", "child-src", "referrer")

# Checks if csp contains directives that are deprecated in CSP3.
#' @rdname csp_security_checkers
#' @export
check_deprecated <- function(csp_df) {

  csp_df <- ensure_csp_df(csp_df)

  deprecated <- csp_df[csp_df[["directive"]] %in% DEPRECATED_DIRECTIVES,]
  if (nrow(deprecated)) {
    return(
      mk_finding(
        category = "deprecated-directive",
        severity = "INFO",
        message = paste0(c(
          "Found deprecated directive(s). See ",
          "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
          "for more information."
        ), collapse = " "),
        where = deprecated
      )
    )
  }

}

# Checks if csp nonce is at least 8 characters long & base64 charset.
#' @rdname csp_security_checkers
#' @export
check_nonce_length <- function(csp_df) {

  csp_df <- ensure_csp_df(csp_df)

  findings <- list()

  nonce <- csp_df[grepl("^nonce-", csp_df[["value"]]),]
  if (nrow(nonce)) {

    idx <- which(nchar(sub("^nonce-", "", nonce[["value"]])) < 8)
    if (length(idx)) {
      findings[[length(findings)+1]] <- mk_finding(
        category = "nonce-length",
        severity = "MEDIUM",
        message = "Nonces should be at least 8 characters long.",
        where = nonce[idx,]
      )
    }

    which(grepl(
      "^[-A-Za-z0-9+=]{1,50}|=[^=]|={3,}$",
      sub("^nonce-", "", nonce[["value"]])
    )) -> idx
    if (length(idx)) {
      findings[[length(findings)+1]] <- mk_finding(
        category = "nonce-charset",
        severity = "INFO",
        message = "Nonces should only use the base64 charset.",
        where = nonce[idx,]
      )
    }

  }

  if (length(findings)) {
    class(findings) <- c("csp_finding_list")
    findings
  } else {
    invisible(NULL)
  }

}

# checks for http:// as src val
#' @rdname csp_security_checkers
#' @export
check_src_http <- function(csp_df) {
  csp_df <- ensure_csp_df(csp_df)
  http <- csp_df[grepl("^http://", csp_df[["value"]]),]
  if (nrow(http)) {
    return(
      mk_finding(
        category = "http-src",
        severity = "MEDIUM",
        message = "Use HTTPS vs HTTP.",
        where = http
      )
    )
  }
}


#' Printer for CSP findings
#'
#' @param x CSP
#' @param ... ignored
#' @keywords internal
#' @export
print.csp_finding <- function(x, ...) {

  cat(sprintf("Category: %s
Severity: %s
 Message: %s

", x$category, x$severity, x$message))

  print(x$where)

  cat("\n")

}

#' Printer for CSP findings
#'
#' @param x CSP
#' @param ... ignored
#' @keywords internal
#' @export
print.csp_finding_list <- function(x, ...) {
  for (f in x) {
    print(f)
    cat("\n", sep="")
  }
}
