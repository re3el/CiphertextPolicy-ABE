#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
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

char* pub_file = "pub_key";
char* msk_file = "master_key";

int main( int argc, char** argv )
{
    element_t alpha;
    element_t a;
    element_t temp;

    struct wabe_pub_s* pub;
    struct wabe_msk_s* msk;    
    
    pub = (struct wabe_pub_s *)malloc(sizeof(struct wabe_pub_s));
    msk = (struct wabe_msk_s *)malloc(sizeof(struct wabe_msk_s));    
    
    pub->pairing_desc = strdup(TYPE_A_PARAMS);
    pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

    //pbc_demo_pairing_init(pairing, argc, argv);

    element_init_G1((pub)->g,           pub->p);
  
    element_init_G1((pub)->g_hat_a,     pub->p);
   // element_init_G2((pub)->gp,        pub->p);
    element_init_GT((pub)->e_hat_alpha, pub->p);
    
    element_init_Zr(alpha,               pub->p);
    element_init_Zr(a,                  pub->p);
    element_init_G2((msk)->g_alpha,     pub->p);
    element_init_GT(temp, pub->p);
    
    /* compute */
    
    element_random(alpha);//Choose alpha, a \in Z_p
    element_random(a);
    element_random((pub)->g);
   
    
    element_pow_zn((pub)->g_hat_a,(pub)->g,a); //Calculate g^a
    element_pow_zn((msk)->g_alpha,(pub)->g,alpha); //Calculate g^alpha
    pairing_apply((pub)->e_hat_alpha,(pub)->g,(msk)->g_alpha, pub->p); //Calculate e_hat_alpha=e(g,g)^{\alpha}


	spit_file(pub_file, wabe_pub_serialize(pub), 1);
	spit_file(msk_file, wabe_msk_serialize(msk), 1);

	return 0;
}
