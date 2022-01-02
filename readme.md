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
```

### Questions
1. Tentang info yg tampil di command line, apakah itu dlam byte biasa, array byte, bit, ascii.
> A: info yang ditampilkan merupakan cuplikan bytes dari frame yang akan di transfer. beserta dengan panjang bytenya per frame. adapun format data yang ditampilkan, itu otomatis menggunakan pengkodean ASCII, makanya ada beberapa symbol yang aneh �. gunanya adalah untuk debugging/membandingkan antara data yg dikirim Server dan yg diterima Client

2. Trus arti num dalam command prompt saat streaming
> A: num atau SeqNum merupakan nomor urutan dr RTSP yang ada didalam session (handshake antar Client-Server). adapun nomor ini otomatis digenerate oleh Client ketika melakukan klik Play/Pause

3. RTP paket yg di diolah di rtppacket.java (kurang lebih fields header2nya ngerti)
> A: header terdiri dari 12 array byte. dimulai dr index 0 yang berisi Version, Padding, Extension dan CC. index 1 berisi  Marker dan PayloadType (disini menggunakan MJPEG_TYPE = 26). index 2 dan 3 berisi SequenceNumber yg merupakan nomor urutan frame. index 4, 5, 6, 7 berisi timestamp dr frame video yg dikirim. index 8, 9, 10, 11 berisi Ssrc

4. status "DHON" apakah itu sama dengan "Ready" 
> A: Status DHON merepresentasikan jikalau enkripsi telah aktif


5. Tentang variabel objek 'datapacket' apakah itu isinya frame terenkripsi atau gmna? dan 'bitstream' yg itu isi dari konversi data yang mana
> A: datapacket atapun datagrampacket merupakan format data yg akan dikirimkan melalui protokol RTSP/RTP. format ini memiliki packet, host tujuan dan port tujuan. sedangkan bitstream adalah data dari frame video yang akan dikonversi/diubah bentuk ke dalam data packet, enkripsi terjadi pada tahap bitstream ini.

6. demo program saat enkripsi dgn kuncinya yg benar dan salah, juga statu2 yg ada di command line
> [Demo](https://drive.google.com/file/d/1GN-yRemVg5EJ25x5O1JcV7wGfndz8kMA/view?usp=sharing)

