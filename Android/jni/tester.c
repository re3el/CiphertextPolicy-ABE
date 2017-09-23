#include <jni.h>
#include <gmp.h>
#include <android/log.h>
#include "include/tester.h"

JNIEXPORT jstring JNICALL Java_com_example_myproject_MainActivity_doSomething( JNIEnv* env, jobject thiz )
{
	int a;
	a = 10;

	mpz_t b,c,sum;
	mpz_inits(b,c,sum,NULL);
	mpz_set_str(b,"1234",10);
	mpz_set_str(c,"5678",10);
	mpz_add(sum,b,c);

	__android_log_print(ANDROID_LOG_WARN,"NATIVE", "C int: %d, mpz_int: %s",a,mpz_get_str(NULL,10,sum));
	//return a;
	return (*env)->NewStringUTF(env, "Hello from JNI !");
}
