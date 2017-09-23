
#include <jni.h>
#include <gmp.h>
#include <pbc.h>
#include <pbc_test.h>
#include <android/asset_manager.h>
#include <android/log.h>
#include "tester.h"
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <assert.h>
#include <string.h>
#include <glib.h>
#include <errno.h>


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


#define LOG_TAG "CPABE_NATIVE"
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

//Public_key

struct wabe_pub_s
{
    //char* pairing_desc;
    //pairing_t p;
    element_t g;           /* G_1 */
    element_t g_hat_a;     /* G_1 */
    element_t e_hat_alpha; /* G_T */
    //element_t g_hat_alpha; /* G_T */
};

//Master Secret Key

struct wabe_msk_s
{
    //element_t beta;    /* Z_r */
    element_t g_alpha; /* G_1 */
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


void wabe_keygen( struct wabe_pub_s* pub, struct wabe_msk_s* msk, struct wabe_pvt_r*, pairing_t pairing);

struct wabe_ciphertext * wabe_encrypt( struct wabe_pub_s* pub, char *Msg, element_t **M, int l, int n, element_t *rho, pairing_t pairing);

void wabe_decrypt( struct wabe_pub_s* pub, struct wabe_pvt_r *pvt, struct wabe_ciphertext *cph, element_t **M, char **enc_attr, int l, int n, element_t *rho, pairing_t pairing, int *chk);

int check(int cnt, int numAtt, char* str, char** att, char** comAtt, int *comAttCnt);
int string_check(int cnt, char *str,char **att, int numAtt, int *chk, char **comAtt);

void calcU(int n, element_t **tempM, element_t *u, pairing_t pairing);
void multiply(int m,int n,int p,int q,element_t **first,element_t **second,element_t *mult,pairing_t pairing);

void lsssMatrix(int *l, int *n, int cnt, signed long int **M, char **L);

void init_aes( element_t k, int enc, AES_KEY* key);
int init_ctr(struct ctr_state *state, const unsigned char iv[16]);
void fencrypt(char* read, char* write, element_t k);
void fdecrypt(char* read, char* write, element_t k);


JNIEXPORT jstring JNICALL Java_com_example_myproject_MainActivity_doSomething( JNIEnv* env, jobject thiz, jobject assetManager)
{
    pairing_t pairing;
    char* p_desc;
    element_t alpha;
    element_t a;
    element_t temp;

    struct wabe_pub_s* pub;
    struct wabe_msk_s* msk;

    struct wabe_pvt_r* pvt;  //one private key of one user, to be changed to array of pvt keys

    pub = (struct wabe_pub_s *)malloc(sizeof(struct wabe_pub_s));
    msk = (struct wabe_msk_s *)malloc(sizeof(struct wabe_msk_s));

    p_desc = strdup(TYPE_A_PARAMS);
    pairing_init_set_buf(pairing, p_desc, strlen(p_desc));
    //pbc_demo_pairing_init(pairing, argc, argv);

    element_init_G1((pub)->g,           pairing);

    element_init_G1((pub)->g_hat_a,     pairing);
   // element_init_G2((pub)->gp,        pairing);
    element_init_GT((pub)->e_hat_alpha, pairing);

    element_init_Zr(alpha,               pairing);
    element_init_Zr(a,                  pairing);
    element_init_G2((msk)->g_alpha,     pairing);
    element_init_GT(temp, pairing);

    /* compute */

    element_random(alpha);//Choose alpha, a \in Z_p
    element_random(a);
    element_random((pub)->g);


    element_pow_zn((pub)->g_hat_a,(pub)->g,a); //Calculate g^a
    element_pow_zn((msk)->g_alpha,(pub)->g,alpha); //Calculate g^alpha
    pairing_apply((pub)->e_hat_alpha,(pub)->g,(msk)->g_alpha, pairing); //Calculate e_hat_alpha=e(g,g)^{\alpha}

    pairing_apply(temp, (pub)->g, (pub)->g, pairing);
    element_pow_zn(temp, temp, alpha);

    /***Printf statements to verify that parameters are correctly calculated ***/
    /*
    element_printf("system parameter alpha = %B\n", alpha);
    element_printf("system parameter a = %B\n", a);
    element_printf("system parameter (pub)->g_hat_a = %B\n", (pub)->g_hat_a);
    element_printf("system parameter (pub)->e_hat_alpha = %B\n", (pub)->e_hat_alpha);
    element_printf("system parameter (msk)->g_alpha = %B\n", (msk)->g_alpha);
    element_printf("system parameter temp = %B\n", temp);  //check if temp = e(g,g)^{\alpha}
    */

    pvt = (struct wabe_pvt_r *)malloc(sizeof(struct wabe_pvt_r));

    element_init_G2(pvt->K,  pairing);
    element_init_G2(pvt->L,  pairing);

    pvt->K_x = g_array_new(0, 1, sizeof(struct wabe_pvt_comp));

    int i;
    //printf("User number %d\n",i);
    wabe_keygen(pub,msk,pvt,pairing);  // Generate secret keys for user using mater secret key

    char Msg[20];
    signed long int **Mat;  //LSSS matrix temp
    element_t **M;
    int l,n,cnt=0;

    // printf("Enter message to encrypt\n");  //currently this is not required. Message can be read from file
    // scanf("%s",Msg);  //Encryption of message done using block ciphers like AES
    // printf("Enter number of attributes in the policy\n");
    // scanf("%d",&l);
    // printf("Enter number of columns in the policy\n");
    // scanf("%d",&n);

    int ch;
    FILE *fptr;
    fptr = fopen("/sdcard/string.txt","r");
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
    printf("\nRows(l):%d, Columns(n):%d\n",l,n);

    LOGE("\n");
    LOGE("Attributes in Policy:\n");
    for(i=0;i<l;i++)
        puts(L[i]);
    LOGE("\n");

    // element_t LSSS matrix
    M = (element_t **)malloc(l*sizeof(element_t *));
     for(i=0;i<l;i++){
     M[i]=(element_t *)malloc(n*sizeof(element_t ));
     }

    int j;
    for(i=0;i<l;i++){
        for(j=0;j<n;j++){
            element_init_Zr(M[i][j], pairing);
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
        element_init_G2(rho[i], pairing);
        element_from_hash(rho[i], enc_attr[i], strlen(enc_attr[i])); //H(x)
    }

    struct wabe_ciphertext *cph;

    cph = (struct wabe_ciphertext *)malloc(sizeof(struct wabe_ciphertext));

    cph =  wabe_encrypt(pub,Msg,M,l,n,rho,pairing);  //Calling Encryption function.

    //redundant, just for checking.
    /*
    element_t ci,ki;
    element_t temp1,temp2;
    element_init_G1(ci,pairing);
    element_init_G2(ki,pairing);
    element_init_GT(temp1,pairing);
    element_init_GT(temp2,pairing);

    for(i=0;i<3;i++){
        element_set(ci,g_array_index( cph->cx, element_t,i ));
        pairing_apply(temp1,ci,pvt->L,pairing);
        //element_printf("main : temp1 = %B\n",temp1);
        element_set(ki,g_array_index(pvt->K_x, struct wabe_pvt_comp,i).hk_x);
        element_printf("ki = %B\n",ki);
        pairing_apply(temp2,cph->c,ki,pairing);
        element_printf("main : temp2 = %B\n",temp2);

    }

    printf("Main: Number of elements in GArray= %d\n", cph->cx->len);
    */
    int chk;
    wabe_decrypt(pub,pvt,cph,M,enc_attr,l,n,rho,pairing,&chk);  //Calling Decryption function.

    element_clear(temp);
    element_clear(alpha);
    element_clear(a);

    if(chk==1)
    	return (*env)->NewStringUTF(env, "Victory! You can Decipher :D");
    else
    	return (*env)->NewStringUTF(env, "Oops, Better luck next time!");
}



void wabe_keygen( struct wabe_pub_s* pub, struct wabe_msk_s* msk, struct wabe_pvt_r* pvt, pairing_t pairing)
{
    int i;
    element_t t;
    element_t at;
    element_t temp;
    element_init_Zr(t,pairing);
    element_init_Zr(at,pairing);
    element_init_G1(temp,pairing);
    element_random(t);
    //element_printf("random t= %B\n", t);
    //element_mul(at, pub->a, t);
    element_pow_zn(temp,pub->g_hat_a,t);
    element_mul(pvt->K,temp,msk->g_alpha);  //K=g^alpha g^at

    element_pow_zn(pvt->L,pub->g,t); //L = g^t

    int no_attr_attributes;  // Number of attributes of a user

    // printf("Enter no of the attributes of user ");
    // scanf("%d", & no_attr_attributes);

    FILE * fp;
    char line[256];
    fp = fopen("/sdcard/usr_att.txt", "r");
    fscanf(fp,"%s",line);
    no_attr_attributes = atoi(line);
    LOGE("int: %d\n", no_attr_attributes);
    //no_attr_attributes = 5;

    char** attr;
    attr = (char **)malloc(no_attr_attributes*sizeof(char *));
    for(i =0;i<no_attr_attributes;i++){
        attr[i] = (char *)malloc(sizeof(char));
    }
    //attr = {"hey","this","a","by","Dr.Ruj"};
//    attr[0] = "hey";
//    attr[1] = "this";
//    attr[2] = "a";
//    attr[3] = "by";
//    attr[4] = "Dr.Ruj";
    i = 0;
    LOGD("Enter attribute strings: \n");
    while (fscanf(fp,"%s",line)==1)
    {
    	//LOGE("line: %s", line[i]);
    	strcpy(attr[i],line);
    	LOGE("attr[i]: %s", attr[i]);
    	i++;
    }
    fclose(fp);

    //printf("\nEnter %d attribute strings\n",no_attr_attributes);
    for(i =0;i<no_attr_attributes;i++){
        struct wabe_pvt_comp c;
        //attr[i] = (char *)malloc(sizeof(char));
        //scanf("%s",attr[i]);
        c.attr = attr[i];
        element_init_G2(c.hk_x, pairing);

        element_from_hash(c.hk_x, c.attr, strlen(c.attr)); //H(x)
        element_printf("hash x= %B\n", c.hk_x);
        element_pow_zn(c.hk_x,c.hk_x,t);  //H(x)^t

        element_printf("secret key K_x= %B\n", c.hk_x);
        g_array_append_val(pvt->K_x, c);

    }


    /***Testing ***/
    /*
    printf("Number of elements in GArray= %d\n", pvt->K_x->len);

    char  *s;
    s = g_array_index( pvt->K_x, struct wabe_pvt_comp, 1 ).attr;
    printf( "retrieving %s\n", s );
    s = g_array_index( pvt->K_x, struct wabe_pvt_comp, 2 ).attr;
    printf( "retrieving %s\n", s );

    element_printf("system parameter pvt K= %B\n", pvt->K);
    element_printf("system parameter pvt L= %B\n", pvt->L);
    element_printf("system parameter temp= %B\n", temp);
    */
    /***End Testing ***/

    element_clear(t);
    element_clear(at);
    element_clear(temp);

}

struct wabe_ciphertext * wabe_encrypt( struct wabe_pub_s* pub, char *Msg,element_t **M, int l, int n, element_t *rho, pairing_t pairing)
{
    int i,j;
    element_t s;  // secret s
    element_t ms; //-s
    element_t z;
    element_t *v;
    element_init_Zr(s,pairing);
    element_init_Zr(ms,pairing);
    element_init_Zr(z,pairing);

    element_random(s);
    element_printf("Original secret s= %B\n", s);


    //choose vector v
    v = (element_t *) malloc(n*(sizeof (element_t)));
    element_init_Zr(v[0],pairing);
    element_set(v[0],s);
    for(i=1;i<n;i++){
        element_init_Zr(v[i],pairing);
        element_random(z);
        element_set(v[i],z);
    }
   /** Print vector v
    printf("vector v = (");
    for(i=0;i<n;i++){
        element_printf("%B\t ",v[i]);
    }
   printf(")\n");
*/

   /*
    element_t **lambda;
    lambda = (element_t **)malloc(n*(sizeof (element_t *)));
    for(i=0;i<l;i++){
        lambda[i] = (element_t *)malloc(n*(sizeof (element_t)));
        for(int j=0;j<n;j++){
            element_init_Zr(lambda[i][j],pairing);
        }
    }*/



    LOGE("Calculate and Print lambda");
    element_t temp;
    element_init_Zr(temp, pairing);

    element_t *lambda;
    lambda = (element_t *)malloc(l*(sizeof (element_t)));
    for(i=0;i<l;i++){
        element_init_Zr(lambda[i],pairing);
        element_set0(lambda[i]);
        for(j=0;j<n;j++){
            element_mul(temp,v[j],M[i][j]);
            element_add(lambda[i],temp,lambda[i]);
        }
    }

    /* "key" is the encryption key. This key is used for encrypting message using AES.
     This is the key that is encrypted. The user has to decrypt and get back this key ***/

    element_t key;
    element_init_GT(key,  pairing);
    struct wabe_ciphertext *cph;
    cph = (struct wabe_ciphertext *)malloc(sizeof(struct wabe_ciphertext));

    element_init_GT(cph->cs,  pairing);
    element_init_G1(cph->c,  pairing);

    cph->cx = g_array_new(0, 1, sizeof(element_t));

    element_random(key);
    element_printf("\nOriginal msg= %B\n", key);  //For check later

    fencrypt("/sdcard/plain.txt", "/sdcard/enc.txt", key);

    element_pow_zn(cph->cs, pub->e_hat_alpha, s);
    element_printf("Value text e(g,g)^alphas = %B\n",cph->cs);  //For check later
    element_mul(cph->cs, cph->cs, key);


    element_pow_zn(cph->c, pub->g, s);



    for(i=0;i<l;i++){

        element_t temp1, temp2, temp3;
        element_init_G1(temp1, pairing);
        element_init_G1(temp2, pairing);
        element_init_G1(temp3, pairing);

        element_t rt;
        element_init_G1(rt, pairing);
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


void wabe_decrypt( struct wabe_pub_s* pub, struct wabe_pvt_r *pvt, struct wabe_ciphertext *cph, element_t **M, char **enc_attr, int l, int n, element_t *rho, pairing_t pairing, int *chk)
{
    long int *w;
    long int *I;
    long int *Ival;
    long int x;
    I = (long int *)malloc(l*sizeof(long int));
    Ival = (long int *)malloc(l*sizeof(long int));
    char *str_temp;
    //char *att, *comAtt;
    char *str;

    element_t temp1, temp2,temp3, temp4, temp5, ci,ki;
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_GT(temp3, pairing);
    element_init_GT(temp4, pairing);
    element_init_GT(temp5, pairing);
    element_init_G1(ci, pairing);
    element_init_G2(ki, pairing);

    //Finding the set I, the attributes which are common in access policy and key.
    int k=0; //k is the size of set I
    int i,j,f;
    int cnt;

    /*Checking if the user has enough matching attributes. StringCheck function is called to do this*/
    /* StringCheck also returns the minimum number of attributes that are enough to satisfy the
    access policy***/
    //printf("Checking if decryption is possible\n");
    cnt=0;
    FILE *fptr;
    fptr = fopen("/sdcard/string.txt","r");
    while((fgetc(fptr))!=EOF)
        cnt++;
    //cnt--;
    rewind(fptr);

    str = (char*)malloc(cnt*sizeof(char));
    fscanf(fptr,"%s",str);
    LOGE("\nString: %s\n",str);
    LOGE("cnt:%d, strlen:%d",cnt,strlen(str));
    fclose(fptr);
    LOGE("\n\nChecking if decryption is possible:");

    int numAtt=pvt->K_x->len;
    //printf("\nNumber of Attributes(numAtt): %d",numAtt);
    //att = (char*)malloc(numAtt*sizeof(char));  //Attributes with the user
    //comAtt = (char*)malloc(numAtt*sizeof(char));  //Attributes common to user and access policy
    //printf("Attributes read %d\n",numAtt);

    char** att;
    att = (char **)malloc(numAtt*sizeof(char *));
    for(i=0;i<numAtt;i++)
        att[i] = (char *)malloc(sizeof(char));

    char** comAtt;
    comAtt = (char **)malloc(numAtt*sizeof(char *));
    for(i=0;i<numAtt;i++)
        comAtt[i] = (char *)malloc(sizeof(char));

    for(i=0;i<numAtt;i++){
        str_temp=g_array_index( pvt->K_x, struct wabe_pvt_comp, i ).attr;
        att[i]=str_temp;  //each attribute is an alphabet
    }

    LOGE("\n\nUser Attributes(att): \n");
    for(i=0;i<numAtt;i++)
        LOGE("%s ",att[i]);
    LOGE("\n");


    *chk=0;
    int comAttCnt; // Number of common Attributes
    comAttCnt = string_check(cnt,str,att,numAtt,chk,comAtt);

    if(*chk==1)
    {
		LOGE("Common Attributes(comAtt): \n");
		for(i=0;i<comAttCnt;i++)
			LOGE("%s ",comAtt[i]);
		LOGE("\n");

		// printf("\n\nenc_attr: \n");
		// for(i=0;i<l;i++)
		//     printf("%s ",enc_attr[i]);
		// printf("\n");


		for(i=0;i<comAttCnt;i++){
			for(j=0;j<l;j++){
				if(strcmp(comAtt[i],enc_attr[j])==0){
				//if(comAtt[i]==enc_attr[j][0]){
					I[k]=j;  //position in ciphertext
					for(f=0;f<numAtt;f++){
						if(strcmp(att[f],comAtt[i])==0)
							Ival[k]=f; //position in secret key
					}
					k++;
				}
			}
		}

		/***Check set I ****/

		// printf("Print the set I\n");
		// for(i=0;i<k;i++)
		//     printf("%ld, %ld ",I[i],Ival[i]);
		// printf("\n");


		/* Read part of LSSS matrix into M1 needed for inverse calculation */

		element_t **M1;
		M1 = (element_t **)malloc(n*sizeof(element_t *));
		for(i=0;i<n;i++)
		{
			M1[i]=(element_t *)malloc(n*sizeof(element_t ));
		}
		for(i=0;i<n;i++)
		{
			for(j=0;j<n;j++)
			{
				element_init_Zr(M1[i][j], pairing);
			}
		}
		int r;
		int m=0;

		for(i=0;i<comAttCnt;i++){
			r = I[i];
			for(j=0;j<n;j++){
				element_set(M1[m][j],M[r][j]);
			}
			m++;
		}

		LOGE("\nMatrix M1: \n");
		for(i=0;i<comAttCnt;i++){
			for(j=0;j<n;j++)
			{
				element_printf("%B ",M1[i][j]);
			}
			LOGE("\n");
		}


		int *redCol;
		redCol=(int *)malloc((n-comAttCnt)*sizeof(int));
		m=0;
		for(i=0;i<n;i++){
			chk=0;
			for(j=0;j<comAttCnt;j++){
				if(!element_is0(M1[j][i])){
					chk=1;
					break;
				}
			}
			if(chk==0){
				redCol[m]=i;  //Redundant column
				m++;
			}
		}
		//m contains the number of redundant colums.
		LOGE("\nNumber of redundant cols = %d\nRed col = ",m);
		for(i=0;i<m;i++) {
			LOGE("%d ", redCol[i]);
		}
		LOGE("\n");

		//find the reduced matrix by eliminating redundant columns

		int *goodCol;  //goodCol helps to trim the columns to get a square matrix
		goodCol=(int *)malloc((n-m)*sizeof(int));

		r=0;j=0;
		for(i=0;i<n;i++){
			if(redCol[r]!=i){
				goodCol[j]=i;
				j++;
			}
			else
				r++;
		}

		LOGE("Good rows: \n");
		for(i=0;i<j;i++){
			LOGE("(%d %d) ",i,goodCol[i]);
		}
		LOGE("\n");



		element_t **tempM, **Mat;
		int z = comAttCnt;
		//printf("Number of columns in final matrix = %d\n", n-m);
		tempM = (element_t **)malloc(z*sizeof(element_t *));
		for(i=0;i<z;i++)
		{
			tempM[i]=(element_t *)malloc((n-m)*sizeof(element_t ));
		}
		for(i=0;i<z;i++)
		{
			for(j=0;j<((n-m));j++)
			{
				element_init_Zr(tempM[i][j], pairing);
			}
		}


		for(i=0;i<z;i++){
			for(j=0;j<(n-m);j++){
				element_set(tempM[i][j],M1[i][goodCol[j]]);
			}
		}

		LOGE("\nReduced Matrix: \n");
		for(i=0;i<z;i++){
			for(j=0;j<(n-m);j++)
			{
				element_printf("%B ",tempM[i][j]);
			}
			LOGE("\n");
		}


		// Transpose of the Reduced matrix
		Mat = (element_t **)malloc(z*sizeof(element_t *));
		for(i=0;i<z;i++)
		{
			Mat[i]=(element_t *)malloc((n-m)*sizeof(element_t ));
		}

		for(i=0;i<z;i++)
		{
			for(j=0;j<((n-m));j++)
			{
				element_init_Zr(Mat[i][j], pairing);
			}
		}

		for(i=0;i<z;i++)
		{
			for(j=0;j<((n-m));j++)
				element_set(Mat[i][j],tempM[j][i]);
		}

		LOGE("\nTranspose of Reduced Matrix: \n");
		for(i=0;i<z;i++){
			for(j=0;j<(n-m);j++)
			{
				element_printf("%B ",Mat[i][j]);
			}
			printf("\n");
		}

		element_t *u;
		u = (element_t *)malloc((n-m)*(sizeof(element_t)));
		for(i=0;i<(n-m);i++)
			element_init_Zr(u[i], pairing);


		calcU(n-m, Mat, u, pairing);


		LOGE("\nPrinting array u\n");
		for ( i=0;i<k;i++){
			element_printf("%B\n",u[i]);
		}


		// w = (long int *)malloc(l*sizeof(long int));
		// for(i=0;i<l;i++)
		//     w[i]=0;
		// //printf("\nGet the values of w\n");  //this should later have to be calculated.

		// for (i=0;i<k;i++){
		//     //scanf("%ld",&w[I[i]]);
		//     element_set_si(u[i],w[I[i]]);
		//     //element_printf("%B \n", u[i]);
		// }


		element_set1(temp4);

		for(i=0;i<k;i++){
			x= I[i];  //finding the row of M where the element belongs
			//printf("pos in ciphertext x = %ld\n", x);
			element_set(ci,g_array_index( cph->cx, element_t,x ));

			//element_printf("Element ci %B\n",ci);//delete
			pairing_apply(temp1,ci,pvt->L,pairing);
			x=Ival[i];  //find the position of the attribute in the ciphertext.
			//printf("pos in secret key x = %ld \n", x);
			element_set(ki,g_array_index( pvt->K_x, struct wabe_pvt_comp,x ).hk_x);
			//element_printf("Element ki%B\n",ki);
			pairing_apply(temp2,cph->c,ki,pairing);
			//element_printf("temp1 = %B, temp2 = %B\n",temp1,temp2);
			element_mul(temp3,temp1,temp2);
			element_pow_zn(temp3,temp3,u[i]);
			element_mul(temp4,temp4,temp3);
		}

		pairing_apply(temp2,cph->c,pvt->K,pairing);

		element_div(temp3,temp2,temp4);
		element_printf("\nDecrypted text e(g,g)^alphas = %B\n",temp3); //Check with initial value
		element_div(temp4,cph->cs,temp3);
		element_printf("Decrypted text = %B\n",temp4);//Check with initial value of key

		fdecrypt("/sdcard/enc.txt", "/sdcard/dec.txt", temp4);

        for(i=0;i<n;i++)
            free(M1[i]);
        free(M1);

        free(redCol);
        free(goodCol);

        for(i=0;i<z;i++)
        {
            free(tempM[i]);
            free(Mat[i]);
        }
        free(tempM);
        free(Mat);

        free(u);
    }

    free(str);

    for(i=0;i<numAtt;i++)
    {
        free(att[i]);
        free(comAtt[i]);
    }
    free(att);
    free(comAtt);
}

int string_check(int cnt, char *str,char **att, int numAtt, int *chk, char **comAtt)
{
    int i;
    int comAttCnt=0;
    *chk = check(cnt,numAtt,str,att,comAtt,&comAttCnt);
    //printf("k = %d\n", *comAttCnt);

    if(*chk==1)
    {
        LOGE("\nVictory! You can decipher :D\n\n");
        // printf("Common Attributes string: \n");
        // for(i=0;i<(comAttCnt);i++)
        //     printf("%s ",comAtt[i]);
        // printf("\n");
    }

    else {
        LOGE("\nOops, hack it better next time!\n");
        //exit(1);
    }

    return comAttCnt;
}



int check(int cnt, int numAtt, char* str, char** att, char** comAtt, int *comAttCnt)
{
    int i,j,thr,res;
    res = 0; // checker for string acceptance
    thr = str[cnt-2] - '0';

    //char *tmpAtt = (char*)malloc(numAtt*sizeof(char)); // temp common attributes

    char** tmpAtt;
    tmpAtt = malloc(numAtt*sizeof(char *));
    for(i=0;i<numAtt;i++)
        tmpAtt[i] = (char *)malloc(sizeof(char));

    int k1 = 0;

    i=1;
    while(str[i]!=')')
    {
        if(str[i]=='(')
        {
            int count = 1; // for getting the substring indices
            char *tempStr = calloc(cnt,sizeof(char)); // to store the substring
            i++;
            j=i-1;

            while(count!=0)
            {
                if(str[i]=='(')
                    count++;
                else if(str[i]==')')
                    count--;
                i++;
            }

            strncpy(tempStr,str+j,i-j);
            tempStr[i]='\0';
            //printf("\ntempStr: %s\n",tempStr);
            res += check(i-j,numAtt,tempStr,att,comAtt,comAttCnt);
            free(tempStr);
        }

        else if(str[i]==',')
            i++;

        else
        {
            //printf("hello, str[i]:%c\n",str[i]);
            char *attStr = calloc(cnt,sizeof(char));
            j=i;
            while(!(str[i]==',' || str[i]=='(' || str[i]==')'))
            {
                //j++;
                i++;
                //printf("str[i]:%c\n",str[i]);
            }
            //printf("i:%d, j:%d, str[i-j]:%c\n",i,j,str[i-j]);
            strncpy(attStr,str+j,i-j);
            attStr[i]='\0';

            //printf("attStr:%s\n",attStr);

            for(j=0;j<numAtt;j++)
            {
                if(strcmp(attStr,att[j])==0)
                {
                    //printf("k1:%d\n",k1);
                    strcpy(tmpAtt[k1],att[j]);
                    //printf("Matched- attStr: %s, tmpAtt[k1]: %s\n",attStr,tmpAtt[k1]);
                    k1++;
                    res++;
                    break;
                }

            }
            //i++;
            free(attStr);
        }

        if(res==thr)
        {
            for(i=0;i<k1;i++)
            {
                strcpy(comAtt[*comAttCnt],tmpAtt[i]);
                //printf("comAtt:%s ",comAtt[*comAttCnt]);
                (*comAttCnt)++;
            }
            //printf("\n");
            break;
        }

    }


    for(i=0;i<numAtt;i++)
        free(tmpAtt[i]);
    free(tmpAtt);

    if(res==thr)
        return 1;
    else
        return 0;

}


void calcU(int n, element_t **ele_mat, element_t *ele_res, pairing_t pairing)
{

    int i, j, k, temp;
    int chk=0;

    element_t q,r,val1;
    element_init_Zr(q,pairing);
    element_init_Zr(r,pairing);
    element_init_Zr(val1,pairing);

    // 2D array declared to store augmented matrix (n*2n)
    element_t **augMat;
    augMat = malloc(n*sizeof(element_t *));
    for(i=0;i<n;i++)
    {
        augMat[i] = malloc(2*n*sizeof(element_t));
    }

    for(i=0;i<n;i++)
    {
        for(j=0;j<2*n;j++)
        {
            element_init_Zr(augMat[i][j], pairing);
        }
    }

    // Declaring Inverse Matrix (n*n)
    element_t **ele_inv;
    ele_inv = malloc(n*sizeof(element_t *));
    for(i=0;i<n;i++)
    {
        ele_inv[i] = malloc(n*sizeof(element_t));
    }

    for(i=0;i<n;i++)
    {
        for(j=0;j<n;j++)
        {
            element_init_Zr(ele_inv[i][j], pairing);
        }
    }


    // Declaring element_t b Matrix (n*1)
    element_t **ele_b;
    ele_b = (element_t **)malloc(n*sizeof(element_t *));
    for(i=0;i<n;i++)
    {
        ele_b[i]=(element_t *)malloc(1*sizeof(element_t ));
    }

    for(i=0;i<n;i++)
    {
        for(j=0;j<1;j++)
        {
            element_init_Zr(ele_b[i][j], pairing);
        }
    }

    // Assigning b matrix:
    for(i=0;i<n;i++)
    {
        if(i==0)
        {
            //b[i][0] = 1;
            element_set1(ele_b[i][0]);
        }
        else
        {
            //b[i][0] = 0;
            element_set0(ele_b[i][0]);
        }

    }

    // storing augmented matrix as a matrix of n (n*2n) in 2D array
    for(i=0; i<n; i++)
    {
        for(j=0; j<n; j++)
            element_set(augMat[i][j],ele_mat[i][j]);
    }

    // augmenting with identity matrix of similar ns
    for(i=0;i<n; i++)
    {
        for(j=n; j<2*n; j++)
        {
            if(i==j%n)
                element_set1(augMat[i][j]);
            else
                element_set0(augMat[i][j]);
        }
    }

    // using Gauss-Jordan elimination
    for(j=0; j<n; j++)
    {
        temp=j;

        // partial pivoting to remove divide by '0' case
        if(element_is0(augMat[temp][j]))
        {
            for(i=j+1; i<n; i++)
            {
                if(!element_is0(augMat[i][j]))
                {
                    temp = i;
                    chk++;
                    break;
                }
            }
        }

        // swapping row which has '0' column element
        if(chk==1)
        {
            for(k=0; k<2*n; k++)
            {
                element_set(q,augMat[j][k]);
                element_set(augMat[j][k],augMat[temp][k]);
                element_set(augMat[temp][k],q);
            }
            chk--;
        }

        // performing row operations to form required identity matrix out of the input matrix
        for(i=0; i<n; i++)
        {
            if(i!=j)
            {
                element_set(r,augMat[i][j]);

                for(k=0; k<2*n; k++)
                {
                    element_div(val1,augMat[j][k],augMat[j][j]);
                    element_mul(val1,val1,r);
                    element_sub(augMat[i][k],augMat[i][k],val1);
                }
            }

            else
            {
                element_set(r,augMat[i][j]);
                for(k=0; k<2*n; k++)
                {
                    element_div(augMat[i][k],augMat[i][k],r);
                }

            }
        }
    }


    // displaying inverse of the non-singular matrix
    LOGE("\nInverse Matrix: \n");
    for(i=0; i<n; i++)
    {
        for(j=0; j<n; j++)
        {
            element_set(ele_inv[i][j],augMat[i][j+n]);
            element_printf("%B\t",ele_inv[i][j]);
        }
        printf("\n");
    }

    multiply(n,n,n,1,ele_inv,ele_b,ele_res,pairing);

    LOGE("\n\nX Matrix: \n");
    for(i = 0; i < n; i++)
    {
        for(j = 0; j < 1; j++)
        {
            //printf("%f\t",res[i][j]);
            element_printf("%B\t",ele_res[i]);
        }
        LOGE("\n");
    }

}

void multiply(int m,int n,int p,int q,element_t **first,element_t **second,element_t *mult,pairing_t pairing)
{
    int i, j, k;

    //float sum = 0;
    element_t sum,tmp;
    element_init_Zr(sum,pairing);
    element_set0(sum);
    element_init_Zr(tmp,pairing);  // for storing temp calculations

    if (n != p)
        LOGE("\n\nMatrices with entered orders can't be multiplied with each other.\n");
    else
    {
        for (i = 0; i < m; i++)
        {
            for (j = 0; j < q; j++)
            {
                for (k = 0; k < p; k++)
                {
                    //sum = sum + first[i][k]*second[k][j];
                    element_mul(tmp,first[i][k],second[k][j]);
                    element_add(sum,sum,tmp);

                }
                //mult[i][j] = sum;
                element_set(mult[i],sum);
                //sum = 0;
                element_set0(sum);
            }
        }

    }

}




void lsssMatrix(int *l, int *n, int cnt, signed long int **M, char **L)
{
    char ch,thr,*Fa,*Fz;
    int z,i,j,m,d;

    z=0;
    m=1;
    d=1;

    Fa = (char*)malloc(cnt*sizeof(char));
    Fz = (char*)malloc(cnt*sizeof(char));

    LOGE("\nString from file: ");
    FILE *fptr;
    fptr = fopen("/sdcard/string.txt","r");
    fscanf(fptr,"%s",Fa);
    fclose(fptr);
    puts(Fa);

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
