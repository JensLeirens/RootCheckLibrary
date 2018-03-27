#include <jni.h>
#include <string>
#include <stdio.h>
#include <android/log.h>

// LOGCAT
#define  LOG_TAG    "RootCheckerNative"
#define  LOGD(...)  if (DEBUG) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__);

/* Set to 1 to enable debug log traces. */
static int DEBUG = 1;

/*****************************************************************************
 * Description: Sets if we should log debug messages
 *
 * Parameters: env - Java environment pointer
 *      thiz - javaobject
 * 	bool - true to log debug messages
 *
 *****************************************************************************/
void Java_com_leirens_jens_rootcheckernative_MainActivity_setLogDebugMessages( JNIEnv* env, jobject thiz, jboolean debug)
{
    if (debug){
        DEBUG = 1;
    }
    else{
        DEBUG = 0;
    }
}

/*****************************************************************************
 * Description: Checks for root binaries
 *
 * Parameters: env - Java environment pointer
 *      thiz - javaobject
 *
 * Return an array of Ints with the length of the paths
 *
 *****************************************************************************/
extern "C"
JNIEXPORT jintArray JNICALL
Java_com_leirens_jens_rootchecklib_RootChecker_checkForRootNative(JNIEnv *env, jobject instance, jobjectArray paths) {

    const jsize length = env->GetArrayLength(paths);
    jintArray binaries = env->NewIntArray(length);
    jint *elements = env->GetIntArrayElements(binaries, NULL);


    int stringCount = (env)->GetArrayLength(paths);

    for (int i=0; i<stringCount; i++) {
        jstring string = (jstring) (env)->GetObjectArrayElement(paths, i);
        const char *pathString = (env)->GetStringUTFChars(string, 0);

        FILE *file;
        if ((file = fopen(pathString, "r")))
        {
            LOGD("LOOKING FOR BINARY: %s PRESENT",pathString);
            fclose(file);
            elements[i] = 1 ;
        } else {
            LOGD("LOOKING FOR BINARY: %s Absent",pathString);
            elements[i] = 0 ;
        }


        (env)->ReleaseStringUTFChars(string, pathString);
    }
    env ->ReleaseIntArrayElements(binaries, elements, NULL);
    return binaries ;

}