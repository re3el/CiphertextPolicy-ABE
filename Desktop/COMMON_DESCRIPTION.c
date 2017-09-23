/// Description of functions used in common.c file

/* These functions are used to read from a file, write to a file and pop an error message if there is a problem in doing the same */
FILE* fopen_read_or_die( char* file );
FILE* fopen_write_or_die( char* file );
void die(char* fmt, ...);

/* Transfers the information from a GByteArray to FILE */
void spit_file( char* file, GByteArray* b, int free );

/* Transfers the information from a FILE to GByteArray*/
GByteArray* suck_file( char* file );

/* Serialize from a string to GByteArray-needed in public and private key serialization/unserialization */
void serialize_string( GByteArray* b, char* s );

/* Unserialize from GByteArray back to string-needed in public and private key serialization/unserialization */
char* unserialize_string( GByteArray* b, int* offset );

/* Serialize a uint32_t variable to GByteArray-needed in element variable serialization/unserialization */
void serialize_uint32( GByteArray* b, uint32_t k );

/* Unserialize a GByteArray back to uint32_t variable-needed in element variable serialization/unserialization */
uint32_t unserialize_uint32( GByteArray* b, int* offset );

/* Serialize an element variable to GByteArray-needed in public,private,msk serialization/unserialization */
void serialize_element( GByteArray* b, element_t e );

/* Unserialize a GByteArray back to element variable-needed in public,private,msk serialization/unserialization */
void unserialize_element( GByteArray* b, int* offset, element_t e );

/* Serialize a pub_key to GByteArray */
GByteArray* wabe_pub_serialize( struct wabe_pub_s* pub );

/* Unserialize a GyteArray back to pub_key */
struct wabe_pub_s* wabe_pub_unserialize( GByteArray* b, int free );

/* Serialize a msk_key to GByteArray */
GByteArray* wabe_msk_serialize( struct wabe_msk_s* msk );

/* Unserialize a GyteArray back to msk_key */
struct wabe_msk_s* wabe_msk_unserialize( struct wabe_pub_s* pub, GByteArray* b, int free );

/* Serialize a priv_key to GByteArray */
GByteArray* wabe_prv_serialize( struct wabe_pvt_r* prv );

/* Unserialize a GyteArray back to priv_key */
struct wabe_pvt_r* wabe_prv_unserialize( struct wabe_pub_s* pub, GByteArray* b, int free );

/* Serialize a Cipher_key to GByteArray */
GByteArray* wabe_cph_serialize(struct wabe_ciphertext* cph);

/* Unserialize a GyteArray back to Cipher_key */
struct wabe_ciphertext* wabe_cph_unserialize( struct wabe_pub_s* pub, GByteArray* b, int free );
