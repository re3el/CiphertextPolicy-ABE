#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <openssl/aes.h>
#include "common.h"



char* pub_file = 0;
char* plain_file = 0;
char* cph_file = "cipher_key";

struct wabe_ciphertext * wabe_encrypt( struct wabe_pub_s* pub, element_t **M, int l, int n, element_t *rho);

void parse_args( int argc, char** argv )
{
	int i;
	for( i = 1; i < argc; i++ )
	{
		if( !pub_file )
		{
			pub_file = argv[i];
		}
        else if(!plain_file)
        {
            plain_file = argv[i];
        }
	}
}

int main( int argc, char** argv )
{
	struct wabe_pub_s* pub;
	struct wabe_ciphertext* cph;

	parse_args(argc, argv);

	pub = wabe_pub_unserialize(suck_file(pub_file), 1);

    signed long int **Mat;  //LSSS matrix temp
    element_t **M;
    int i,l,n,cnt=0;

    int ch;
    FILE *fptr;
    fptr = fopen("string.txt","r");
    while((ch=fgetc(fptr))!=EOF)
        cnt++;
    fclose(fptr);

    Mat = (signed long int **)malloc(cnt*sizeof(signed long int *));
    for(i=0;i<cnt;i++){
        Mat[i]=(signed long int *)malloc(cnt*sizeof(signed long int ));
    }

    char **L;
    L = (char **)malloc(cnt * sizeof(char *));
    for (i=0;i<cnt;i++){
        L[i] = (char *)malloc(cnt * sizeof(char));
    }

    lsssMatrix(&l,&n,cnt,Mat,L);
    //printf("\nRows(l):%d, Columns(n):%d\n",l,n);

    //printf("\n");
    //printf("Attributes in Policy:\n");
    //for(i=0;i<l;i++)
        //puts(L[i]);
    //printf("\n");

    // element_t LSSS matrix
    M = (element_t **)malloc(l*sizeof(element_t *));
     for(i=0;i<l;i++){
     M[i]=(element_t *)malloc(n*sizeof(element_t ));
     }

    int j;
    for(i=0;i<l;i++){
        for(j=0;j<n;j++){
            element_init_Zr(M[i][j], pub->p);
        }
    }

    // Read policy LSSS matrix
    for(i=0;i<l;i++)
    {
        for(j=0;j<n;j++)
            element_set_si(M[i][j], Mat[i][j]);
    }

    char **enc_attr;  // This array contains the list of attributes in the encryption policy
    element_t *rho;   // maps element/row into H(attribute)
    enc_attr = (char **)malloc(l*sizeof(char *));
    rho = (element_t *)malloc(l*sizeof(element_t));
    for(i =0;i<l;i++){
        enc_attr[i] = (char *)malloc(sizeof(char));
        //printf("Enter attribute strings\n");
        //scanf("%s",enc_attr[i]);
        strcpy(enc_attr[i],L[i]);
        element_init_G2(rho[i], pub->p);
        element_from_hash(rho[i], enc_attr[i], strlen(enc_attr[i])); //H(x)
    }

	cph = (struct wabe_ciphertext *)malloc(sizeof(struct wabe_ciphertext));
    cph = wabe_encrypt(pub,M,l,n,rho);

	spit_file(cph_file, wabe_cph_serialize(cph), 1);
	
	return 0;
}


struct wabe_ciphertext * wabe_encrypt( struct wabe_pub_s* pub, element_t **M, int l, int n, element_t *rho)
{
    int i,j;
    element_t s;  // secret s
    element_t ms; //-s
    element_t z;
    element_t *v;
    element_init_Zr(s,pub->p);
    element_init_Zr(ms,pub->p);
    element_init_Zr(z,pub->p);

    element_random(s);
    //element_printf("Original secret s= %B\n", s);


    //choose vector v
    v = (element_t *) malloc(n*(sizeof (element_t)));
    element_init_Zr(v[0],pub->p);
    element_set(v[0],s);
    for(i=1;i<n;i++){
        element_init_Zr(v[i],pub->p);
        element_random(z);
        element_set(v[i],z);
    }

    //printf("Calculate and Print lambda");
    element_t temp;
    element_init_Zr(temp, pub->p);

    element_t *lambda;
    lambda = (element_t *)malloc(l*(sizeof (element_t)));
    for(i=0;i<l;i++){
        element_init_Zr(lambda[i],pub->p);
        element_set0(lambda[i]);
        for(j=0;j<n;j++){
            element_mul(temp,v[j],M[i][j]);
            element_add(lambda[i],temp,lambda[i]);
        }
    }

    /* "key" is the encryption key. This key is used for encrypting message using AES.
     This is the key that is encrypted. The user has to decrypt and get back this key ***/

    element_t key;
    element_init_GT(key,  pub->p);
    struct wabe_ciphertext *cph;
    cph = (struct wabe_ciphertext *)malloc(sizeof(struct wabe_ciphertext));

    element_init_GT(cph->cs,  pub->p);
    element_init_G1(cph->c,  pub->p);

    cph->cx = g_array_new(0, 1, sizeof(element_t));

    element_random(key);
    //element_printf("\nOriginal msg= %B\n", key);  //For check later

    fencrypt(plain_file, "enc.txt", key);

    element_pow_zn(cph->cs, pub->e_hat_alpha, s);
    //element_printf("Value text e(g,g)^alphas = %B\n",cph->cs);  //For check later
    element_mul(cph->cs, cph->cs, key);
    element_pow_zn(cph->c, pub->g, s);

    for(i=0;i<l;i++){

        element_t temp1, temp2, temp3;
        element_init_G1(temp1, pub->p);
        element_init_G1(temp2, pub->p);
        element_init_G1(temp3, pub->p);

        element_t rt;
        element_init_G1(rt, pub->p);
        element_pow_zn(temp1,rho[i],s);
        element_invert(temp1,temp1);
        element_pow_zn(temp2,pub->g_hat_a,lambda[i]);
        element_mul(temp3, temp1,temp2);
        g_array_append_val(cph->cx, temp3);

        element_clear(temp1);
        element_clear(temp2);
        element_clear(rt);
    }

    element_clear(temp);

    element_clear(s);
    element_clear(z);

    return(cph);

}