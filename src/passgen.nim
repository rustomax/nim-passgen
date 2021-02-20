## Cross-platform password generation library in Nim.
## 
## * [GitHub Repo](https://github.com/rustomax/nim-passgen)
## * Used by [npg](https://github.com/rustomax/npg) - Nim Password Generator, command-line password generation utility
## * Random number generator provided by the excellent [nimcrypto](https://github.com/cheatfate/nimcrypto) library
##
## Generated passwords conform to a schema, based on parameters passed
## to `newPassGen()` function. Currently two parameters are available:
## * Password length `passlen = x`, where `x` is an integer between 4 and 1024
## * Flags specifying which sets of characters are used in generated passwords.
##   4 character sets are supported:
##   * `fUpper` - ASCII uppercase letters: `A .. Z`
##   * `fLower` - ASCII lowercase letters: `a .. z`
##   * `fDigits` - Digits: `0 .. 9`
##   * `fSpecial` - "password-friendly" special characters: `! # $ % @ = ^ * + -`
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

import nimcrypto, strutils

type
    CFlag* = enum
        fUpper
        fLower
        fDigits
        fSpecial

    PasswordGenerator* = object
        passLen: int
        flags: set[CFlag]

    ArgumentException* = object of ValueError

const
    ## Flag set including all available characters
    allFlags = {fUpper, fLower, fDigits, fSpecial}

    # default random byte buffer length
    bufferLen = 2048

    # password length boundaries
    minPassLen = 4
    maxPassLen = 1024

    # ASCII range of characters
    bottomAscii = 33
    topAscii = 127

    # Password-friendly special characters
    specialChars = {'!', '#', '$', '%', '@', '=', '^', '*', '+', '-'}

proc getRandomAscii(): string =
    ## Returns a variable length ASCII string of randomly generated characters
    
    var buffer: array[bufferLen, uint8]
    let count = randomBytes(addr buffer[0], bufferLen - 1)

    result = ""

    for i in 0..count:
        if buffer[i] >= bottomAscii and buffer[i] <= topAscii:
            result &= $char(buffer[i])

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
    ## **Caveat 1:**
    ##
    ## Minimum and maximum password length is set `4` and `1024` characters respectively.
    ## Boundary checking is in general a good thing; plus I don't see a practical
    ## use-case where a password or a numerical pin length would fall outside of these parameters. 
    ##
    ## **Caveat 2:**
    ##
    ## When more than one character set are specified in the `flags` parameter,
    ## there is no *guarantee* that characters from a particular set will actually appear
    ## in the generated password, since each letter in the password is included probabilistically.
    ## For instance, adding `fSpecial` to the list of flags does not guarantee that a special
    ## character will *definitely* appear in the generated password. The `fSpecial` flag simply
    ## indicates to the password generator that special characters *may* be included in the password.
    ## This is especially true for shorter passwords (i.e. 8 characters-long).
    ##
    ## If the `flags` argument is omitted or is explicitly empty (`flags = {}`), all character sets will be included.
    ## In other words, the following blocks are identical:
    ##
    ## .. code-block:: Nim
    ##   # These three blocks mean exactly the same thing
    ##   block:
    ##       let pg = newPassGen(flags = {fLower, fUpper, fDigits, fSpecial})
    ##   block:
    ##       let pg = newPassGen(flags = {})
    ##   block:
    ##       let pg = newPassGen()
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

    # Argument sanity checks
    if passlen < minPassLen or passlen > maxPassLen:
        raise newException(ArgumentException, "invalid argument passlen: " & $passlen)
    
    result.passLen = passlen
    if flags == {}:
        result.flags = allFlags
    else:
        result.flags = flags        

proc getPassword*(generator: PasswordGenerator): string =
    ## Returns a new (set) of randomly generated password(s)
    ##
    ## **Example:**
    ##
    ## .. code-block:: Nim
    ##   # Prints five 32 character-long random passwords
    ##   # containing letters and digits (no special characters)
    ##   var pg = newPassGen(passlen = 32, flags = {fLower, fUpper, fDigits})
    ##   for i in 1..5:
    ##      echo pg.getPassword()

    result = ""
    while result.len < generator.passLen:
        let rawChars = getRandomAscii()
        for i in 0..rawChars.len - 1:
            if generator.flags.contains(fLower) and isLowerAscii(rawChars[i]):
                result &= rawChars[i]
            if generator.flags.contains(fUpper) and isUpperAscii(rawChars[i]):
                result &= rawChars[i]
            if generator.flags.contains(fDigits) and isDigit(rawChars[i]):
                result &= rawChars[i]
            if generator.flags.contains(fSpecial) and specialChars.contains(rawChars[i]):
                result &= rawChars[i]
            if result.len >= generator.passLen:
                return
