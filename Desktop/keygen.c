#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <sys/stat.h>
#include <pbc_random.h>
#include <openssl/aes.h>
#include "common.h"

#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"



char*  pub_file = 0;
char*  msk_file = 0;
char*  usrAtt_file = 0;
char*  out_file = "priv_key";

void parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
	{

		if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
        else if( !usrAtt_file )
        {
            usrAtt_file = argv[i];
        }

	}
}

int main( int argc, char** argv )
{
	struct wabe_pub_s* pub;
    struct wabe_msk_s* msk;
    struct wabe_pvt_r* pvt; 

	parse_args(argc, argv);

	pub = wabe_pub_unserialize(suck_file(pub_file), 1);
	msk = wabe_msk_unserialize(pub, suck_file(msk_file), 1);

	pvt = (struct wabe_pvt_r *)malloc(sizeof(struct wabe_pvt_r));
    element_init_G2(pvt->K,  pub->p);
    element_init_G2(pvt->L,  pub->p);
    pvt->K_x = g_array_new(0, 1, sizeof(struct wabe_pvt_comp));

    int i;
    element_t t;
    element_t at;
    element_t temp;
    element_init_Zr(t,pub->p);
    element_init_Zr(at,pub->p);
    element_init_G1(temp,pub->p);
    element_random(t);
    element_pow_zn(temp,pub->g_hat_a,t);
    element_mul(pvt->K,temp,msk->g_alpha);  //K=g^alpha g^at
    element_pow_zn(pvt->L,pub->g,t); //L = g^t

    int no_attr_attributes;  // Number of attributes of a user
    FILE * fp;
    char line[256];
    fp = fopen(usrAtt_file, "r");
    fscanf(fp,"%s",line);
    no_attr_attributes = atoi(line);
    //printf("int: %d\n", no_attr_attributes);

    char** attr;
    attr = (char **)malloc(no_attr_attributes*sizeof(char *));
    for(i =0;i<no_attr_attributes;i++){
        attr[i] = (char *)malloc(sizeof(char));
    }

    i = 0;
    //printf("Enter attribute strings: \n");
    while (fscanf(fp,"%s",line)==1)
    {
    	//LOGE("line: %s", line[i]);
    	strcpy(attr[i],line);
    	//printf("attr[i]: %s", attr[i]);
    	i++;
    }
    fclose(fp);

    //printf("\nEnter %d attribute strings\n",no_attr_attributes);
    for(i =0;i<no_attr_attributes;i++){
        struct wabe_pvt_comp c;
        //attr[i] = (char *)malloc(sizeof(char));
        //scanf("%s",attr[i]);
        c.attr = attr[i];
        element_init_G2(c.hk_x, pub->p);

        element_from_hash(c.hk_x, c.attr, strlen(c.attr)); //H(x)
        //element_printf("hash x= %B\n", c.hk_x);
        element_pow_zn(c.hk_x,c.hk_x,t);  //H(x)^t

        //element_printf("secret key K_x= %B\n", c.hk_x);
        g_array_append_val(pvt->K_x, c);

    }

	spit_file(out_file, wabe_prv_serialize(pvt), 1);

    element_clear(t);
    element_clear(at);
    element_clear(temp);

	return 0;
}