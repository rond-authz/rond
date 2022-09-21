
package policies

allow_all {
    true
}

verify_authorization {
    jwe := parse_jwe(input.request.headers)
    jwe.ftype == "EXTERNAL"
}
