#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <openssl/aes.h>
#include <pbc.h>

#include "common.h"


void die(char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
}

FILE* fopen_read_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "r")) )
		die("can't read file: %s\n", file);

	return f;
}

FILE* fopen_write_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "w")) )
		die("can't write file: %s\n", file);

	return f;
}

void spit_file( char* file, GByteArray* b, int free )
{
	FILE* f;

	f = fopen_write_or_die(file);
	fwrite(b->data, 1, b->len, f);
	fclose(f);

	if( free )
		g_byte_array_free(b, 1);
}

GByteArray* suck_file( char* file )
{
	FILE* f;
	GByteArray* a;
	struct stat s;

	a = g_byte_array_new();
	stat(file, &s);
	g_byte_array_set_size(a, s.st_size);

	f = fopen_read_or_die(file);
	fread(a->data, 1, s.st_size, f);
	fclose(f);

	return a;
}

void serialize_string( GByteArray* b, char* s )
{
	g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
}

char* unserialize_string( GByteArray* b, int* offset )
{
	GString* s;
	char* r;
	char c;

	s = g_string_sized_new(32);
	while( 1 )
	{
		c = b->data[(*offset)++];
		if( c && c != EOF )
			g_string_append_c(s, c);
		else
			break;
	}

	r = s->str;
	g_string_free(s, 0);

	return r;
}

void serialize_uint32( GByteArray* b, uint32_t k )
{
	int i;
	guint8 byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		g_byte_array_append(b, &byte, 1);
	}
}

uint32_t unserialize_uint32( GByteArray* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b->data[(*offset)++])<<(i*8);

	return r;
}

void serialize_element( GByteArray* b, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	serialize_uint32(b, len);

	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, e);
	g_byte_array_append(b, buf, len);
	free(buf);
}

void unserialize_element( GByteArray* b, int* offset, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len);
	memcpy(buf, b->data + *offset, len);
	*offset += len;

	element_from_bytes(e, buf);
	free(buf);
}

GByteArray* wabe_pub_serialize( struct wabe_pub_s* pub )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  pub->pairing_desc);
	serialize_element(b, pub->g);
	serialize_element(b, pub->g_hat_a);
	serialize_element(b, pub->e_hat_alpha);
	//serialize_element(b, pub->g_hat_alpha);

	return b;
}

struct wabe_pub_s* wabe_pub_unserialize( GByteArray* b, int free )
{
	struct wabe_pub_s* pub;
	int offset;

	pub = (struct wabe_pub_s*) malloc(sizeof(struct wabe_pub_s));
	offset = 0;

	pub->pairing_desc = unserialize_string(b, &offset);
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

	element_init_G1(pub->g,           pub->p);
	element_init_G1(pub->g_hat_a,     pub->p);
	//element_init_G2(pub->gp,          pub->p);
	element_init_GT(pub->e_hat_alpha, pub->p);

	unserialize_element(b, &offset, pub->g);
	unserialize_element(b, &offset, pub->g_hat_a);
	//unserialize_element(b, &offset, pub->gp);
	unserialize_element(b, &offset, pub->e_hat_alpha);

	if( free )
		g_byte_array_free(b, 1);

	return pub;
}


GByteArray* wabe_msk_serialize( struct wabe_msk_s* msk )
{
	GByteArray* b;

	b = g_byte_array_new();
	//serialize_element(b, msk->beta);
	serialize_element(b, msk->g_alpha);

	return b;
}

struct wabe_msk_s* wabe_msk_unserialize( struct wabe_pub_s* pub, GByteArray* b, int free )
{
	struct wabe_msk_s* msk;
	int offset;

	msk = (struct wabe_msk_s*) malloc(sizeof(struct wabe_msk_s));
	offset = 0;

	//element_init_Zr(msk->beta, pub->p);
	element_init_G2(msk->g_alpha, pub->p);

	//unserialize_element(b, &offset, msk->beta);
	unserialize_element(b, &offset, msk->g_alpha);

	if( free )
		g_byte_array_free(b, 1);

	return msk;
}


GByteArray* wabe_prv_serialize( struct wabe_pvt_r* prv )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();

	serialize_element(b, prv->K);
	serialize_element(b, prv->L);
	serialize_uint32(b, prv->K_x->len);

	for( i = 0; i < prv->K_x->len; i++ )
	{
		serialize_string(b, g_array_index(prv->K_x, struct wabe_pvt_comp, i).attr);
		serialize_element(b, g_array_index(prv->K_x, struct wabe_pvt_comp, i).hk_x);
		//serialize_element(b, g_array_index(prv->K_x, wabe_prv_comp_t, i).dp);
	}

	return b;
}

struct wabe_pvt_r* wabe_prv_unserialize( struct wabe_pub_s* pub, GByteArray* b, int free )
{
	struct wabe_pvt_r* prv;
	int i;
	int len;
	int offset;

	prv = (struct wabe_pvt_r*) malloc(sizeof(struct wabe_pvt_r));
	offset = 0;

	element_init_G2(prv->K, pub->p);
	unserialize_element(b, &offset, prv->K);

	element_init_G2(prv->L, pub->p);
	unserialize_element(b, &offset, prv->L);

	prv->K_x = g_array_new(0, 1, sizeof(struct wabe_pvt_comp));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		struct wabe_pvt_comp c;

		c.attr = unserialize_string(b, &offset);

		element_init_G2(c.hk_x,  pub->p);
		//element_init_G2(c.dp, pub->p);

		unserialize_element(b, &offset, c.hk_x);
		//unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->K_x, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return prv;
}


GByteArray* wabe_cph_serialize(struct wabe_ciphertext* cph)
{
	int i;
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, cph->cs);
	serialize_element(b, cph->c);
	serialize_uint32(b, cph->cx->len);

	for( i = 0; i < cph->cx->len; i++ )
	{
		//serialize_string(b, g_array_index(prv->K_x, struct wabe_pvt_comp, i).attr);
		serialize_element(b, g_array_index(cph->cx, element_t, i));
		//serialize_element(b, g_array_index(prv->K_x, wabe_prv_comp_t, i).dp);
	}


	return b;
}

struct wabe_ciphertext* wabe_cph_unserialize( struct wabe_pub_s* pub, GByteArray* b, int free )
{
	struct wabe_ciphertext* cph;
	int i,len,offset;

	cph = (struct wabe_ciphertext*) malloc(sizeof(struct wabe_ciphertext));
	offset = 0;

	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	unserialize_element(b, &offset, cph->cs);
	unserialize_element(b, &offset, cph->c);
	
	//cph->p = unserialize_policy(pub, b, &offset);
	cph->cx = g_array_new(0, 1, sizeof(element_t));
	len = unserialize_uint32(b, &offset);

	for( i = 0; i < len; i++ )
	{
		element_t c;
		//struct wabe_pvt_comp c;

		//c.attr = unserialize_string(b, &offset);

		//element_init_G2(c.hk_x,  pub->p);
		//element_init_G2(c.dp, pub->p);

		element_init_G1(c, pub->p);
		unserialize_element(b, &offset, c);
		//unserialize_element(b, &offset, c.dp);

		g_array_append_val(cph->cx, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return cph;
}

// void wabe_pub_free( wabe_pub_t* pub )
// {
// 	element_clear(pub->g);
// 	element_clear(pub->h);
// 	element_clear(pub->gp);
// 	element_clear(pub->g_hat_alpha);
// 	pairing_clear(pub->p);
// 	free(pub->pairing_desc);
// 	free(pub);
// }

// void wabe_msk_free( wabe_msk_t* msk )
// {
// 	element_clear(msk->beta);
// 	element_clear(msk->g_alpha);
// 	free(msk);
// }

// void wabe_prv_free( wabe_prv_t* prv )
// {
// 	int i;
	
// 	element_clear(prv->d);

// 	for( i = 0; i < prv->comps->len; i++ )
// 	{
// 		wabe_prv_comp_t c;

// 		c = g_array_index(prv->comps, wabe_prv_comp_t, i);
// 		free(c.attr);
// 		element_clear(c.d);
// 		element_clear(c.dp);
// 	}

// 	g_array_free(prv->comps, 1);

// 	free(prv);
// }

// void wabe_cph_free( wabe_cph_t* cph )
// {
// 	element_clear(cph->cs);
// 	element_clear(cph->c);
// 	wabe_policy_free(cph->p);
// }



void lsssMatrix(int *l, int *n, int cnt, signed long int **M, char **L)
{
    char ch,thr,*Fa,*Fz;
    int z,i,j,m,d;

    z=0;
    m=1;
    d=1;

    Fa = (char*)malloc(cnt*sizeof(char));
    Fz = (char*)malloc(cnt*sizeof(char));

    //printf("\nString from file: ");
    FILE *fptr;
    fptr = fopen("string.txt","r");
    fscanf(fptr,"%s",Fa);
    fclose(fptr);
    //puts(Fa);

    //gets(Fa);

    M[0][0] = 1;
    strcpy(L[0],Fa);

    // z=-1 --> all the threshold strings are covered
    while(z!=-1)
    {
        z=-1; i=0;
        while(i<m && z==-1)
        {
            if(L[i][0] =='(')
                z=i;
            else
                i++;
        }

        if(z!=-1)
        {
            //printf("threshold string present\n");
            strcpy(Fz,L[z]);

            // printf("Fz: ");
            // puts(Fz);
            // printf("\n");

            int m1, d1, m2=0, d2;                               // m2 = children of Fz; d2 = threshold of Fz;

            char **L1;
            L1 = (char **)calloc(cnt, sizeof(char *));
            for (i=0;i<cnt;i++){
                L1[i] = (char *)calloc(cnt, sizeof(char));
            }

            char **L2;
            L2 = (char **)calloc(cnt, sizeof(char *));
            for (i=0;i<cnt;i++){
                L2[i] = (char *)calloc(cnt, sizeof(char));
            }

             signed long int **M1;
             M1 = (signed long int **)calloc(cnt,sizeof(signed long int *));
             for (i=0;i<cnt;i++){
                 M1[i] = (signed long int *)calloc(cnt,sizeof(signed long int));
             }

            // Fz to L2:
            i=1;
            while(Fz[i]!=')')
            {
                if(Fz[i]=='(')
                {
                    i++;
                    int cnt=1;
                    j=i-1;
                    while(cnt!=0)
                    {
                        if(Fz[i]=='(')
                            cnt++;
                        else if(Fz[i]==')')
                            cnt--;
                        i++;
                    }

                    strncpy(L2[m2],Fz+j,i-j);
                    L2[m2][i]='\0';
                    m2++;
                }

                else if((Fz[i]>=97 && Fz[i]<=122) || (Fz[i]>=65 && Fz[i]<=90))
                {
                    char *attStr = calloc(cnt,sizeof(char));
                    j=i;
                    while(!(Fz[i]==',' || Fz[i]=='(' || Fz[i]==')'))
                    {
                        //j++;
                        //printf("Fz[i]:%c\n",Fz[i]);
                        i++;
                    }
                    //printf("i:%d, j:%d, str[i-j]:%c\n",i,j,str[i-j]);
                    strncpy(attStr,Fz+j,i-j);
                    attStr[i]='\0';

                    //printf("attStr:%s\n",attStr);
                    //L2[m2][0]=Fz[i];
                    //L2[m2][1]='\0';
                    strcpy(L2[m2],attStr);
                    m2++;
                    //i++;

                    free(attStr);
                }

                else
                    i++;
            } // end while

            if(Fz[i]==')')
            {
                thr = Fz[i-1];
                d2 = thr-'0';     // threshold value
            }

            // printf("L2: \n");
            // for(i=0;i<m2;i++)
            //     puts(L2[i]);
            // printf("\n");

            // M1=M
            for(i=0;i<m;i++)
            {
                for(j=0;j<d;j++)
                    M1[i][j]=M[i][j];
            }

            // L1=L
            for(i=0;i<m;i++)
                strcpy(L1[i],L[i]);

            m1 = m;
            d1 = d;

            // PART 1
            for(i=0;i<z;i++)
            {
                strcpy(L[i],L1[i]);

                for(j=0; j<d1; j++)
                    M[i][j] = M1[i][j];

                for(j=d1; j<d1+d2-1; j++)
                    M[i][j] = 0;
            }

            // PART 2
            for(i=z; i<z+m2; i++)
            {
                strcpy(L[i],L2[i-z]);

                for(j=0; j<d1; j++)
                    M[i][j] = M1[z][j];

                int a,x;
                a = i-(z-1);
                x = a;

                for(j=d1; j<d1+d2-1; j++)
                {
                    M[i][j] = x;
                    x = (x*a);                                          //modulus p should be added!
                }

            }

            // PART 3
            for(i=z+m2; i<m1+m2; i++)
            {
                strcpy(L[i],L1[i-m2+1]);

                for(j=0; j<d1; j++)
                    M[i][j] = M1[i-m2+1][j];

                for(j=d1; j<d1+d2-1; j++)
                    M[i][j] = 0;
            }

            m = m1+m2-1;
            d = d1+d2-1;

            // printing after every iteration
            // printf("M matrix: \n");
            // for(i=0;i<m;i++)
            // {
            //     for(j=0;j<d;j++)
            //     {
            //         printf("%ld  ",M[i][j]);
            //     }
            //     printf("\n");
            // }
            // printf("\n");
            // printf("L matrix:\n");
            // for(i=0;i<m;i++)
            //     puts(L[i]);
            // printf("\n");
            // printf("\n");

             for (i=0; i<cnt; ++i)
             {
                 free(L1[i]);
                 free(L2[i]);
                 free(M1[i]);
             }

            free(L1);
            free(L2);
            free(M1);
        } // end IF

    } // end while

    free(Fa);
    free(Fz);
    //free(L);
    //free(M);

    *l = m;
    *n = d;
}

FILE *readFile;
FILE *writeFile;
AES_KEY key;

int bytes_read, bytes_written;
unsigned char indata[AES_BLOCK_SIZE];
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
struct ctr_state state;

void init_aes( element_t k, int enc, AES_KEY* key)
{
  int key_len;
  unsigned char* key_buf;

  key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
  key_buf = (unsigned char*) malloc(key_len);
  element_to_bytes(key_buf, k);

  if( enc )
    AES_set_encrypt_key(key_buf + 1, 128, key);
  else
    AES_set_decrypt_key(key_buf + 1, 128, key);
  free(key_buf);

}

int init_ctr(struct ctr_state *state, const unsigned char iv[16])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
     * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

void fencrypt(char* read, char* write, element_t k)
{
    if(!RAND_bytes(iv, AES_BLOCK_SIZE))
    {
        fprintf(stderr, "Could not create random bytes.");
        exit(1);
    }

    readFile = fopen(read,"rb");
    writeFile = fopen(write,"wb");

    if(readFile==NULL)
    {
        fprintf(stderr, "Read file is null.");
        exit(1);
    }

    if(writeFile==NULL)
    {
        fprintf(stderr, "Write file is null.");
        exit(1);
    }

    fwrite(iv, 1, 8, writeFile); // IV bytes 1 - 8
    fwrite("\0\0\0\0\0\0\0\0", 1, 8, writeFile); // Fill the last 4 with null bytes 9 - 16

    //Initializing the encryption KEY
    init_aes(k, 1, &key);
    //printf("hello 1\n");

 //    if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
 //    {
 //        fprintf(stderr, "Could not set encryption key.");
 //        exit(1);
 //    }

    init_ctr(&state, iv); //Counter call
    //Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
    while(1)
    {
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, readFile);
        AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);

        bytes_written = fwrite(outdata, 1, bytes_read, writeFile);
        if (bytes_read < AES_BLOCK_SIZE)
        {
            break;
        }
    }

    fclose(writeFile);
    fclose(readFile);
}

void fdecrypt(char* read, char* write, element_t k)
{

    readFile=fopen(read,"rb");
    writeFile=fopen(write,"wb");

    if(readFile==NULL)
    {
        fprintf(stderr,"Read file is null.");
        exit(1);
    }

    if(writeFile==NULL)
    {
        fprintf(stderr, "Write file is null.");
        exit(1);
    }

    fread(iv, 1, AES_BLOCK_SIZE, readFile);

    //Initializing the encryption KEY
    init_aes(k, 1, &key);
    //printf("hello 2\n");
    // if (AES_set_encrypt_key(enc_key, 128, &key) < 0)
    // {
    //     fprintf(stderr, "Could not set decryption key.");
    //     exit(1);
    // }

    init_ctr(&state, iv);//Counter call
    //Encrypting Blocks of 16 bytes and writing the output.txt with ciphertext
    while(1)
    {
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, readFile);
        //printf("%i\n", state.num);
        AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);

        bytes_written = fwrite(outdata, 1, bytes_read, writeFile);
        if (bytes_read < AES_BLOCK_SIZE)
        {
            break;
        }
    }
    fclose(writeFile);
    fclose(readFile);
}