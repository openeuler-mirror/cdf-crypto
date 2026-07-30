    # Currently, G++ does not support -Wno-format-zero-length.
    TRY_WARN_CC_FLAG(-Wno-format-zero-length)
    # Other flags here may not be supported on some versions of
    # gcc that people want to use.
    for flag in overflow strict-overflow missing-format-attribute missing-prototypes return-type missing-braces parentheses switch unused-function unused-label unused-variable unused-value unknown-pragmas sign-compare newline-eof error=uninitialized no-maybe-uninitialized error=pointer-arith error=int-conversion error=incompatible-pointer-types error=discarded-qualifiers error=implicit-int error=strict-prototypes; do
      TRY_WARN_CC_FLAG(-W$flag)
    done
    #  old-style-definition? generates many, many warnings
