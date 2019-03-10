context("Presence test works")

expect_true(has_csp("https://rud.is/"))

context("Parser works")

x1 <- fetch_csp("https://rud.is/")
expect_is(x1, "csp")

x2 <- parse_csp("default-src 'none'", "https://example.com")
expect_is(x2, "csp")

context("Data framer works")
expect_is(as.data.frame(x1), "data.frame")

context("Validation works")

expect_true(nrow(validate_csp(x1)) > 0)
expect_true(nrow(validate_csp(x2)) == 0)

context("Testers work")

expect_is(allows_unsafe_inline_script(x1), "logical")
expect_is(allows_unsafe_inline_script(x2), "logical")

check_script_unsafe_inline(x2)


structure(list(vulnerable = c(FALSE, TRUE), n = c(3122L, 2837L
)), class = c("tbl_df", "tbl", "data.frame"), .Names = c("vulnerable",
"n"), row.names = c(NA, -2L))

library(waffle)

