# nim-passgen
Password generation library in Nim

* [Full documentation](https://rustomax.github.io/dev/nim/passgen/passgen.html)

### Installation
```sh
nimble install passgen
```

### Example

```nim
    let pg = newPassGen(passlen = 24)
    for i in 1..5:
        echo "Long: ", pg.getPassword()

    let pg = newPassGen(passlen = 8, flags={fUpper, fLower, fDigits})
    for i in 1..5:
        echo "Short: ", pg.getPassword()

    let pg = newPassGen(passlen = 4, flags={fDigits})
    for i in 1..5:
        echo "PIN: ", pg.getPassword()        
```
