//Public_key

struct wabe_pub_s
{
    char* pairing_desc;
    pairing_t p;
    element_t g;           /* G_1 */
    element_t g_hat_a;     /* G_1 */
    element_t e_hat_alpha; /* G_T */
    //element_t g_hat_alpha; /* G_T */
};

//Master Secret Key

struct wabe_msk_s
{
    //element_t beta;    /* Z_r */
    element_t g_alpha; /* G_2 */
};

//Secret Key
struct wabe_pvt_r   //Secret Key
{
    element_t K; /* G_2*/
    element_t L; /* G_2 */
    GArray* K_x;/* wabe_prv_comp's */
};

struct wabe_pvt_comp
{
    
    char* attr;
    element_t hk_x;  /* G_2 */
};

struct wabe_ciphertext
{
    element_t cs; //C
    element_t c; //C'
    GArray* cx;
};

struct ctr_state 
{ 
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num; 
    unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

GByteArray* suck_file( char* file );
void spit_file( char* file, GByteArray* b, int free );

GByteArray* wabe_pub_serialize(struct wabe_pub_s* pub );
GByteArray* wabe_msk_serialize(struct wabe_msk_s* msk );
GByteArray* wabe_prv_serialize(struct wabe_pvt_r* prv );
GByteArray* wabe_cph_serialize(struct wabe_ciphertext* cph );

struct wabe_pub_s* wabe_pub_unserialize(GByteArray* b, int free );
struct wabe_msk_s* wabe_msk_unserialize(struct wabe_pub_s* pub, GByteArray* b, int free );
struct wabe_pvt_r* wabe_prv_unserialize(struct wabe_pub_s* pub, GByteArray* b, int free );
struct wabe_ciphertext* wabe_cph_unserialize(struct wabe_pub_s* pub, GByteArray* b, int free );

void lsssMatrix(int *l, int *n, int cnt, signed long int **M, char **L);

void init_aes( element_t k, int enc, AES_KEY* key);
int init_ctr(struct ctr_state *state, const unsigned char iv[16]);
void fencrypt(char* read, char* write, element_t k);
void fdecrypt(char* read, char* write, element_t k);