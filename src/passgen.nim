## Password generation library in Nim.
##
## Passgen uses `urand` [library](https://github.com/matceporial/nim-urand),
## to generate randomness, although this may change in the future,
## as higher quality random number generators become available in Nim.
##
## Generated passwords conform to a schema, based on parameters passed
## to `newPassGen()` function. Currently two parameters are available:
## * password length `passlen = x`, where `x` is a non-negative integer
## * sets of characters `flags = set[CFlag]` used in generated passwords.
##   3 distinct sets are supported:
##   * `fUpper` - ASCII uppercase letters: `A .. Z`
##   * `fLower` - ASCII lowercase letters: `a .. z`
##   * `fDigits` - Digits: `0 .. 9`
##   * `fSpecial` - "password-friendly" special characters: `! @ # $ %`
##
## **Example:**
## 
## .. code-block:: Nim
##   import passgen
##
##   # Generates a random 12 character-long password,
##   # containing uppercase and lowercase letters, and special characters
##   let pg = newPassGen(passlen = 12)
##   echo pg.getPassword()
##
##   # Generates a random 4 digit-long numerical PIN
##   let pg = newPassGen(passlen = 4, flags={fDigits})
##   echo pg.getPassword()

import urand, strutils, tables

type
    CFlag* = enum
        fUpper
        fLower
        fDigits
        fSpecial

    PasswordGenerator* = object
        passLen: int
        flags: set[CFlag]
        chars: string

    ArgumentException* = object of Exception

const
    ## Flag set including all available characters
    allFlags = {fUpper, fLower, fDigits, fSpecial}

    ## Map of flags to character sets
    charSets = {
        fUpper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        fLower: "abcdefghijklmnopqrstuvwxyz",
        fDigits: "0123456789".repeat(3),
        fSpecial: "!#$%@".repeat(5)
    }.toTable


proc flagsToChars(flags: set[CFlag]): string =
    ## Returns a signle string, containing all
    ## character sets, referenced by a set of flags.
    for flag in flags:
        for c in charSets[flag]:
            result &= c


proc newPassGen*(passlen: int = 16, flags: set[CFlag] = allFlags): PasswordGenerator =
    ## Creates and initializes a new password generator for specific set of parameters
    ##
    ## **Example:**
    ##
    ## .. code-block:: Nim
    ##   # Initializes password generator with default set of parameters:
    ##   # - password length = 16
    ##   # - passwords will include uppercase and lowercase letters,
    ##   #   digits and special characters
    ##   let pg = newPassGen()
    ##
    ## **Example:**
    ##
    ## .. code-block:: Nim
    ##   # Initializes password generator with custom set of parameters:
    ##   # - password length = 24
    ##   # - passwords will include uppercase and lowercase letters
    ##   #   and no special characters
    ##   let pg = newPassGen(passlen = 24, flags = {fLower, fUpper, fDigits})
    ##
    ## **Caveat:**
    ##
    ## When more than one character set are specified in the `flags` parameter,
    ## there is no *guarantee* that characters from a particular set will actually appear
    ## in the generated password, since each letter in the password is included probabilistically.
    ## For instance, adding `fSpecial` to the list of flags does not guarantee that a special
    ## character will *definitely* appear in the generated password. The `fSpecial` flag simply
    ## indicates to the password generator that special characters *may* be included in the password.
    ## This is especially true for shorter passwords (i.e. 8 characters-long).
    ##
    ## If you omit the `flags` parameter, the default,
    ## containing all character sets will be used. In other words, the following 2 blocks are identical:
    ##
    ## .. code-block:: Nim
    ##   # These two blocks mean exactly the same thing
    ##   block:
    ##       let pg = newPassGen(flags = {fLower, fUpper, fDigits, fSpecial})
    ##   block:
    ##       let pg = newPassGen()
    ##    
    ## However, explicitly passing an empty flag set `flags = {}` is not allowed
    ## and will raise an `ArgumentException` error
    ##
    ## .. code-block:: Nim
    ##   # This will raise an error
    ##   let pg = newPassGen(flags = {})
    ##
    ## Mutable password generator variable can be reinitialized with a new set of parameters.
    ##
    ## **Example:**
    ##
    ## .. code-block:: Nim
    ##   var pg = newPassGen(passlen = 20) # will generate 20 character-long passwords
    ##   pg = newPassGen(passlen = 12) # now will generate 12 character-long passwords
    ##
    ## Keep in mind that reinitializing the generator variable resets all
    ## parameters to defaults, unless explicitly overwriten.
    ##
    ## .. code-block:: Nim
    ##   var pg = newPassGen(passlen = 20, flags = {fUpper, fLower, fDigits})
    ##   # Generating 20 character-long passwords,
    ##   # containing only letters and digits (no special characters)
    ##   
    ##   pg = newPassGen(passlen = 12)
    ##   # Now generating 12 character-long passwords,
    ##   # containing letters, digits AND special characters.
    ##
    ##   # If you don't want special characters, you must exclude them explicitly again:
    ##   pg = newPassGen(passlen = 12, flags = {fLower, fUpper, fDigits})
    ##   # Generating 12 character-long passwords,
    ##   # containing only letters and digits (no special characters)

    # Santity checks on arguments
    if passlen < 1:
        raise newException(ArgumentException, "invalid argument passlen: " & $passlen)
    if flags == {}:
        raise newException(ArgumentException, "invalid argument flags: " & $flags)

    result.passLen = passlen
    result.flags = flags
    result.chars = flagsToChars(flags)


proc getPassword*(generator: PasswordGenerator): string =
    ## Returns a new random password
    ##
    ## **Example:**
    ##
    ## .. code-block:: Nim
    ##   # Prints five 32 character-long random passwords
    ##   # containing letters and digits (no special characters)
    ##   var pg = newPassGen(passlen = 32, flags = {fLower, fUpper, fDigits})
    ##   for i in 1..5:
    ##      echo pg.getPassword()
    var ur: Urand
    ur.open()

    var currLen = 0
    while currLen < generator.passLen:
        let c = ur.urand(1)[0].int
        if c < generator.chars.len:
            result.add generator.chars[c]
            currLen += 1

    ur.close()
