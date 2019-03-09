
[![Travis-CI Build
Status](https://travis-ci.org/hrbrmstr/cspy.svg?branch=master)](https://travis-ci.org/hrbrmstr/cspy)
[![Coverage
Status](https://codecov.io/gh/hrbrmstr/cspy/branch/master/graph/badge.svg)](https://codecov.io/gh/hrbrmstr/cspy)
[![CRAN\_Status\_Badge](http://www.r-pkg.org/badges/version/cspy)](https://cran.r-project.org/package=cspy)

# cspy

Content Security Policy Decomposer & Evaluator

## Description

Methods are provided to decompose, display, and validate content
security policy header values. Wraps the ‘Shape Security’ ‘salvation’
Java library (<https://github.com/shapesecurity/salvation>). Package
version tracks ‘salvation’ Java archive version.

## What’s Inside The Tin

The following functions are implemented:

Core:

  - `fetch_csp`: Fetch and/or parse a content security policy header
    value
  - `has_csp`: Does a URL have a content security policy?
  - `parse_csp`: Fetch and/or parse a content security policy header
    value
  - `validate_csp`: Validate a CSP
  - `as.data.frame.csp`: Convert a parsed CSP into a data frame of
    directives and values

Security/Safety Checks:

  - `check_deprecated`: Tests for insecure CSP settings
  - `check_ip_source`: Tests for insecure CSP settings
  - `check_missing_directives`: Tests for insecure CSP settings
  - `check_nonce_length`: Tests for insecure CSP settings
  - `check_plain_url_schemes`: Tests for insecure CSP settings
  - `check_script_unsafe_eval`: Tests for insecure CSP settings
  - `check_script_unsafe_inline`: Tests for insecure CSP settings
  - `check_src_http`: Tests for insecure CSP settings
  - `check_wildcards`: Tests for insecure CSP settings

Testers:

  - `allows_child_from_source`: Tests for what a parsed CSP allows
  - `allows_connect_to`: Tests for what a parsed CSP allows
  - `allows_font_from_source`: Tests for what a parsed CSP allows
  - `allows_form_action`: Tests for what a parsed CSP allows
  - `allows_frame_ancestor`: Tests for what a parsed CSP allows
  - `allows_frame_from_source`: Tests for what a parsed CSP allows
  - `allows_manifest_from_source`: Tests for what a parsed CSP allows
  - `allows_media_from_source`: Tests for what a parsed CSP allows
  - `allows_navigation`: Tests for what a parsed CSP allows
  - `allows_object_from_source`: Tests for what a parsed CSP allows
  - `allows_prefetch_from_source`: Tests for what a parsed CSP allows
  - `allows_script_from_source`: Tests for what a parsed CSP allows
  - `allows_script_with_nonce`: Tests for what a parsed CSP allows
  - `allows_style_from_source`: Tests for what a parsed CSP allows
  - `allows_style_with_nonce`: Tests for what a parsed CSP allows
  - `allows_unsafe_inline_script`: Tests for what a parsed CSP allows
  - `allows_unsafe_inline_style`: Tests for what a parsed CSP allows
  - `allows_worker_from_source`: Tests for what a parsed CSP allows

## Installation

``` r
install.packages("cspy", repos = "https://cinc.rud.is/")
```

## Usage

``` r
library(cspy)
library(tibble) # for printing

# current version
packageVersion("cspy")
## [1] '2.6.0'
```

``` r
has_csp("https://community.rstudio.com")
## [1] TRUE

csp <- fetch_csp("https://community.rstudio.com")

csp
## base-uri
## object-src
## script-src 'unsafe-eval' 'report-sample' https://community.rstudio.com/logs/ https://community.rstudio.com/sidekiq/ https://community.rstudio.com/mini-profiler-resources/ https://community.rstudio.com/assets/ https://community.rstudio.com/brotli_asset/ https://community.rstudio.com/extra-locales/ https://community.rstudio.com/highlight-js/ https://community.rstudio.com/javascripts/ https://community.rstudio.com/plugins/ https://community.rstudio.com/theme-javascripts/ https://community.rstudio.com/svg-sprite/ https://www.google-analytics.com/analytics.js
## worker-src 'self' blob:

(csp_df <- as.data.frame(csp))
## # A tibble: 18 x 3
##    directive  value                                                  origin                       
##    <chr>      <chr>                                                  <chr>                        
##  1 base-uri   'none'                                                 https://community.rstudio.com
##  2 object-src 'none'                                                 https://community.rstudio.com
##  3 script-src 'unsafe-eval'                                          https://community.rstudio.com
##  4 script-src 'report-sample'                                        https://community.rstudio.com
##  5 script-src https://community.rstudio.com/logs/                    https://community.rstudio.com
##  6 script-src https://community.rstudio.com/sidekiq/                 https://community.rstudio.com
##  7 script-src https://community.rstudio.com/mini-profiler-resources/ https://community.rstudio.com
##  8 script-src https://community.rstudio.com/assets/                  https://community.rstudio.com
##  9 script-src https://community.rstudio.com/brotli_asset/            https://community.rstudio.com
## 10 script-src https://community.rstudio.com/extra-locales/           https://community.rstudio.com
## 11 script-src https://community.rstudio.com/highlight-js/            https://community.rstudio.com
## 12 script-src https://community.rstudio.com/javascripts/             https://community.rstudio.com
## 13 script-src https://community.rstudio.com/plugins/                 https://community.rstudio.com
## 14 script-src https://community.rstudio.com/theme-javascripts/       https://community.rstudio.com
## 15 script-src https://community.rstudio.com/svg-sprite/              https://community.rstudio.com
## 16 script-src https://www.google-analytics.com/analytics.js          https://community.rstudio.com
## 17 worker-src 'self'                                                 https://community.rstudio.com
## 18 worker-src blob:                                                  https://community.rstudio.com

allows_unsafe_inline_script(csp)
## [1] FALSE

check_deprecated(csp_df)

check_ip_source(csp_df)

check_missing_directives(csp_df)

check_nonce_length(csp_df)

check_plain_url_schemes(csp_df)

check_script_unsafe_eval(csp_df)
## Category: script-unsafe-eval
## Severity: HIGH
##  Message: 'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().
## 
## # A tibble: 1 x 3
##   directive  value         origin                       
## * <chr>      <chr>         <chr>                        
## 1 script-src 'unsafe-eval' https://community.rstudio.com

check_script_unsafe_inline(csp_df)

check_src_http(csp_df)

check_wildcards(csp_df)
```

## crsspy Metrics

| Lang  | \# Files |  (%) | LoC |  (%) | Blank lines |  (%) | \# Lines |  (%) |
| :---- | -------: | ---: | --: | ---: | ----------: | ---: | -------: | ---: |
| R     |       11 | 0.65 | 509 | 0.73 |         134 | 0.71 |      221 | 0.73 |
| Maven |        1 | 0.06 |  70 | 0.10 |           6 | 0.03 |        5 | 0.02 |
| XML   |        1 | 0.06 |  65 | 0.09 |           0 | 0.00 |        0 | 0.00 |
| Java  |        2 | 0.12 |  26 | 0.04 |           8 | 0.04 |        6 | 0.02 |
| Rmd   |        1 | 0.06 |  21 | 0.03 |          37 | 0.20 |       69 | 0.23 |
| make  |        1 | 0.06 |  11 | 0.02 |           4 | 0.02 |        0 | 0.00 |

## Code of Conduct

Please note that this project is released with a [Contributor Code of
Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree
to abide by its terms.
