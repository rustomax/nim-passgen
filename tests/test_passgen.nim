# To run these tests, execute `nimble test`.
import unittest
import strutils
import passgen

test "can initialize password generator with default settings":
    discard newPassGen()

test "can initialize password generator with custom settings":
    discard newPassGen(passlen = 20, flags = {fUpper, fLower, fSpecial})

test "custom generator returns expected password length":
    check newPassGen(passlen = 20).getPassword().len == 20

test "custom generator returns expected set of characters":
    let generator = newPassGen(passlen = 1000, flags = {fUpper, fLower, fDigits})
    check generator.getPassword().contains({'A'..'z'}) == true
    check generator.getPassword().contains({'0'..'9'}) == true
    check generator.getPassword().contains({'!', '#', '$', '%', '@', '=', '^', '*', '+', '-'}) == false

test "zero password length raises exception":
    expect ArgumentException:
        discard newPassGen(passlen = 0)

test "negative password length raises exception":
    expect ArgumentException:
        discard newPassGen(passlen = -10)

test "can reinitialize mutable generator with a new set of arguments":
    var pg = newPassGen(passlen = 20)
    check pg.getPassword().len == 20
    pg = newPassGen(passlen = 12)
    check pg.getPassword().len == 12