#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <openssl/aes.h>
#include "common.h"


char* pub_file   = 0;
char* prv_file   = 0;
char* cipher_file = 0;
char* enc_file = 0;

int check(int cnt, int numAtt, char* str, char** att, char** comAtt, int *comAttCnt);
int string_check(int cnt, char *str,char **att, int numAtt, int *chk, char **comAtt);

void calcU(int n, element_t **tempM, element_t *u, struct wabe_pub_s* pub);
void multiply(int m,int n,int p,int q,element_t **first,element_t **second,element_t *mult, struct wabe_pub_s* pub);

void wabe_decrypt( struct wabe_pub_s* pub, struct wabe_pvt_r *pvt, struct wabe_ciphertext *cph, element_t **M, char **enc_attr, int l, int n, element_t *rho, int *chk);


void parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
	{
		if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !prv_file )
		{
			prv_file = argv[i];
		}
		else if( !cipher_file )
		{
			cipher_file = argv[i];
		}
		else if( !enc_file )
		{
			enc_file = argv[i];
		}

	}
}

int main( int argc, char** argv )
{
	struct wabe_pub_s* pub;
	struct wabe_pvt_r* prv;
	struct wabe_ciphertext* cph;

	parse_args(argc, argv);

	pub = wabe_pub_unserialize(suck_file(pub_file), 1);
	prv = wabe_prv_unserialize(pub, suck_file(prv_file), 1);
	//printf("hello Test\n");
	cph = wabe_cph_unserialize(pub, suck_file(cipher_file), 1);

	signed long int **Mat;  //LSSS matrix temp
    element_t **M;
    int l,n,cnt=0;

    int i,ch;
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

    // printf("\n");
    // printf("Attributes in Policy:\n");
    // for(i=0;i<l;i++)
    //     puts(L[i]);
    // printf("\n");

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
        strcpy(enc_attr[i],L[i]);
        element_init_G2(rho[i], pub->p);
        element_from_hash(rho[i], enc_attr[i], strlen(enc_attr[i])); //H(x)
    }


	int chk;
    wabe_decrypt(pub,prv,cph,M,enc_attr,l,n,rho,&chk);  //Calling Decryption function.


    // if(chk==1)
    // 	printf("Victory! You can Decipher :D");
    // else
    // 	printf("Oops, Better luck next time!");

	return 0;
}

void wabe_decrypt( struct wabe_pub_s* pub, struct wabe_pvt_r *pvt, struct wabe_ciphertext *cph, element_t **M, char **enc_attr, int l, int n, element_t *rho, int *chk)
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
    element_init_GT(temp1, pub->p);
    element_init_GT(temp2, pub->p);
    element_init_GT(temp3, pub->p);
    element_init_GT(temp4, pub->p);
    element_init_GT(temp5, pub->p);
    element_init_G1(ci, pub->p);
    element_init_G2(ki, pub->p);

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
    fptr = fopen("string.txt","r");
    while((fgetc(fptr))!=EOF)
        cnt++;
    //cnt--;
    rewind(fptr);

    str = (char*)malloc(cnt*sizeof(char));
    fscanf(fptr,"%s",str);
    printf("\nString: %s\n",str);
    //printf("cnt:%d, strlen:%d",cnt,strlen(str));
    fclose(fptr);
    printf("\nChecking if decryption is possible:");

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

    printf("\n\nUser Attributes(att): \n");
    for(i=0;i<numAtt;i++)
        printf("%s ",att[i]);
    printf("\n");


    *chk=0;
    int comAttCnt; // Number of common Attributes
    comAttCnt = string_check(cnt,str,att,numAtt,chk,comAtt);

    if(*chk==1)
    {
		printf("Common Attributes(comAtt): \n");
		for(i=0;i<comAttCnt;i++)
			printf("%s ",comAtt[i]);
		printf("\n");

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
				element_init_Zr(M1[i][j], pub->p);
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

		printf("\nMatrix M1: \n");
		for(i=0;i<comAttCnt;i++){
			for(j=0;j<n;j++)
			{
				element_printf("%B ",M1[i][j]);
			}
			printf("\n");
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
		// printf("\nNumber of redundant cols = %d\nRed col = ",m);
		// for(i=0;i<m;i++) {
		// 	printf("%d ", redCol[i]);
		// }
		// printf("\n");

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

		// printf("Good rows: \n");
		// for(i=0;i<j;i++){
		// 	printf("(%d %d) ",i,goodCol[i]);
		// }
		// printf("\n");



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
				element_init_Zr(tempM[i][j], pub->p);
			}
		}


		for(i=0;i<z;i++){
			for(j=0;j<(n-m);j++){
				element_set(tempM[i][j],M1[i][goodCol[j]]);
			}
		}

		// printf("\nReduced Matrix: \n");
		// for(i=0;i<z;i++){
		// 	for(j=0;j<(n-m);j++)
		// 	{
		// 		element_printf("%B ",tempM[i][j]);
		// 	}
		// 	printf("\n");
		// }


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
				element_init_Zr(Mat[i][j], pub->p);
			}
		}

		for(i=0;i<z;i++)
		{
			for(j=0;j<((n-m));j++)
				element_set(Mat[i][j],tempM[j][i]);
		}

		printf("\nTranspose of Reduced Matrix: \n");
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
			element_init_Zr(u[i], pub->p);


		calcU(n-m, Mat, u, pub);


		printf("\nPrinting array u\n");
		for ( i=0;i<k;i++){
			element_printf("%B\n",u[i]);
		}

		element_set1(temp4);

		for(i=0;i<k;i++){
			x= I[i];  //finding the row of M where the element belongs
			//printf("pos in ciphertext x = %ld\n", x);
			element_set(ci,g_array_index( cph->cx, element_t,x ));

			//element_printf("Element ci %B\n",ci);//delete
			pairing_apply(temp1,ci,pvt->L,pub->p);
			x=Ival[i];  //find the position of the attribute in the ciphertext.
			//printf("pos in secret key x = %ld \n", x);
			element_set(ki,g_array_index( pvt->K_x, struct wabe_pvt_comp,x ).hk_x);
			//element_printf("Element ki%B\n",ki);
			pairing_apply(temp2,cph->c,ki,pub->p);
			//element_printf("temp1 = %B, temp2 = %B\n",temp1,temp2);
			element_mul(temp3,temp1,temp2);
			element_pow_zn(temp3,temp3,u[i]);
			element_mul(temp4,temp4,temp3);
		}

		pairing_apply(temp2,cph->c,pvt->K,pub->p);

		element_div(temp3,temp2,temp4);
		//element_printf("\nDecrypted text e(g,g)^alphas = %B\n",temp3); //Check with initial value
		element_div(temp4,cph->cs,temp3);
		//element_printf("Decrypted text = %B\n",temp4);//Check with initial value of key

		fdecrypt(enc_file, "dec.txt", temp4);

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
        printf("\nVictory! You can decipher :D\n\n");
        // printf("Common Attributes string: \n");
        // for(i=0;i<(comAttCnt);i++)
        //     printf("%s ",comAtt[i]);
        // printf("\n");
    }

    else {
        printf("\nOops, hack it better next time!\n");
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


void calcU(int n, element_t **ele_mat, element_t *ele_res, struct wabe_pub_s* pub )
{

    int i, j, k, temp;
    int chk=0;

    element_t q,r,val1;
    element_init_Zr(q,pub->p);
    element_init_Zr(r,pub->p);
    element_init_Zr(val1,pub->p);

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
            element_init_Zr(augMat[i][j], pub->p);
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
            element_init_Zr(ele_inv[i][j], pub->p);
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
            element_init_Zr(ele_b[i][j], pub->p);
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
    //printf("\nInverse Matrix: \n");
    for(i=0; i<n; i++)
    {
        for(j=0; j<n; j++)
        {
            element_set(ele_inv[i][j],augMat[i][j+n]);
            //element_printf("%B\t",ele_inv[i][j]);
        }
        //printf("\n");
    }

    multiply(n,n,n,1,ele_inv,ele_b,ele_res,pub);

    // printf("\n\nX Matrix: \n");
    // for(i = 0; i < n; i++)
    // {
    //     for(j = 0; j < 1; j++)
    //     {
    //         //printf("%f\t",res[i][j]);
    //         element_printf("%B\t",ele_res[i]);
    //     }
    //     printf("\n");
    // }

}

void multiply(int m,int n,int p,int q,element_t **first,element_t **second,element_t *mult, struct wabe_pub_s* pub)
{
    int i, j, k;

    //float sum = 0;
    element_t sum,tmp;
    element_init_Zr(sum,pub->p);
    element_set0(sum);
    element_init_Zr(tmp,pub->p);  // for storing temp calculations

    if (n != p)
        printf("\n\nMatrices with entered orders can't be multiplied with each other.\n");
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
