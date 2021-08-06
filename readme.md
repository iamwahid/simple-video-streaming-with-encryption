# Simple Video Streaming with AES-Rijndael Encryption Frame

## Requirements
- JDK 8

## How to use

### Compile
```
$ javac Server.java Client.java

```

### Run Server
```
$ java Server [PORT] [EncryptionCode]
```

### Run Client
```
$ java Client [HOST|localhost] [PORT] [EncryptionCode]
```

## Run from Release Files

No compile needed

### Run Server
```
$ java -jar Server.jar [PORT] [EncryptionCode]
```

### Run Client
```
$ java -jar Client.jar [HOST|localhost] [PORT] [EncryptionCode]