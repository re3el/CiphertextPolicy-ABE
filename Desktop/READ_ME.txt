1) SETUP

gcc setup.c common.c -I /home/yogi/gmp-6.0.0 -I /home/yogi/pbc-0.5.14/include/ -L /usr/local/lib -lgmp -lpbc -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include -lglib-2.0 -lssl -lcrypto -g -lm -o setup

./setup

Input: -
Output: Public Key(pub_key), Master Secret Key(master_key)


2) KEYGEN

gcc keygen.c common.c -I /home/yogi/gmp-6.0.0 -I /home/yogi/pbc-0.5.14/include/ -L /usr/local/lib -lgmp -lpbc -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include -lglib-2.0 -lssl -lcrypto -g -lm -o keygen

./keygen pub_key master_key usr_att.txt 

Input : Public Key, Master Secret Key, User Attributes(usr_att.txt)
Output: Private Key(priv_key)


3) ENCRYPTION

gcc enc.c common.c -I /home/yogi/gmp-6.0.0 -I /home/yogi/pbc-0.5.14/include/ -L /usr/local/lib -lgmp -lpbc -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include -lglib-2.0 -lssl -lcrypto -g -lm -o enc

./enc pub_key plain.txt

Input: Public Key, Plain Text Message(plain.txt)
Output: Cipher Key(cipher_key), Encrypted Text(enc.txt)


4) DECRYPTION

gcc dec.c common.c -I /home/yogi/gmp-6.0.0 -I /home/yogi/pbc-0.5.14/include/ -L /usr/local/lib -lgmp -lpbc -I /usr/include/glib-2.0/ -I /usr/lib/glib-2.0/include -lglib-2.0 -lssl -lcrypto -g -lm -o dec

./dec pub_key priv_key cipher_key enc.txt

Input: Public Key, Private Key, Cipher key, Encrypted Text
Output: Decrypted Text(dec.txt)