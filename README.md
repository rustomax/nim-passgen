# nim-passgen
Password generation library in Nim

[![Build Status](https://travis-ci.org/rustomax/nim-passgen.svg?branch=master)](https://travis-ci.org/rustomax/nim-passgen)

* [Full documentation](https://rustomax.github.io/dev/nim/passgen/passgen.html)

### Installation
```sh
nimble install passgen
```

### Example

```nim
# 24 character-long password,
# inluding letters, numbers and special characters
let pg = newPassGen(passlen = 24)
echo "Long: ", pg.getPassword()

# 8 character-long password,
# inluding letters and numbers only (no special characters)
pg = newPassGen(passlen = 8, flags={fUpper, fLower, fDigits})
echo "Short: ", pg.getPassword()

# 4 character-long numerical PIN
pg = newPassGen(passlen = 4, flags={fDigits})
echo "PIN: ", pg.getPassword()
```
