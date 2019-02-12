#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include <jni.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>

#include "inlineHook.h"
#include "dexfile.h"
#include "leb128.h"

#define LOG_TAG    "CSLOG"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, __VA_ARGS__)
#define JNIREG_CLASS "com/winer/proxyapp/ProxyApplication"
#define NELEM(arr)      (sizeof(arr) / sizeof(arr[0]))

#define CLASSES_NAME "classes2.dex"
#define CLASSES_SUB_NAME "/classes.dex"
#define APPLICATION_CLASS ((*env)->FindClass(env, "android/app/Application"))
#define ACTIVITYTHREAD_CLASS ((*env)->FindClass(env, "android/app/ActivityThread"))
#define LOADEDAPK_CLASS ((*env)->FindClass(env, "android/app/LoadedApk"))
#define APPBINDDATA_CLASS ((*env)->FindClass(env, "android/app/ActivityThread$AppBindData"))
#define ITERATOR_CLASS  ((*env)->FindClass(env, "java/util/Iterator"))
#define DEXCLASSLOADER_CLASS ((*env)->FindClass(env,"dalvik/system/DexClassLoader"))

jmethodID currentActivityThreadID;
#define CURRENT_ACTIVITYTHREAD ((*env)->CallStaticObjectMethod(env, ACTIVITYTHREAD_CLASS, currentActivityThreadID))
const char* odex_dir;
const char* odex_path;
const char* dex_path;
//jobject mApplication;
jobject oldApplication;
jobject newApplication;
jstring file_dex_dir_str;
jstring file_odex_dir_str;
jstring file_lib_dir_str;
const char *className = "com.example.forceapkobj.MyApplication";//fixme

const char *dex_base = NULL;
const char *DexFileOpenMemory_fName = "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_7OatFileEPS9_";

const char* getCharsFromStdString(void * string){
    long *chars_addr = (long *)(string + 8);
    LOGD("std::string got: %s",(char*) *chars_addr);
    return ((char*)*chars_addr);
}

int (*old_DexFileOpenMemory)(const char* base,
                              size_t size,
                              const void* location,
                              uint32_t location_checksum,
                              void* mem_map,
                              const void* oat_file,
                              void* error_msg);
int new_DexFileOpenMemory(const char* base,
                           size_t size,
                           const void* location,
                           uint32_t location_checksum,
                           void* mem_map,
                           const void* oat_file,
                           void* error_msg){

    LOGD("openMemory injection started");
    //check locaton
    if(strcmp(getCharsFromStdString(location), dex_path) == 0 )
    {
        dex_base = base;
        LOGD("Geted dex base:%x",dex_base);
    }
    return old_DexFileOpenMemory(base, size, location, location_checksum, mem_map, oat_file, error_msg);
}

int (*old_execve)(const char *path, char *const argv[], char *const envp[]);
int new_execve(const char *path, char *const argv[], char *const envp[]){
        LOGD("execve injection started");
        if(!strcmp(path, "/system/bin/dex2oat")){
            LOGD("catched dex2oat");
            //make dex2oat failed
            return -1;
        }
        return old_execve(path, argv, envp);
}

void *findSymbol(const char *path, const char *symbol) {
    void *handle = dlopen(path, RTLD_LAZY);
    if(!handle) {
        LOGD("handle %s is null", path);
        return NULL;
    }

    //Cydia::MSHookFunction(void *,void *,void **)
    void *target = dlsym(handle, symbol);
    if(!target) {
        LOGD("symbol %s is null", symbol);
    }
    return target;
}
int cs_hook(){
    LOGD("start cs hook");
    void * execve_ptr = findSymbol("/system/lib/libc.so","execve");
    if (execve_ptr == NULL){
        LOGD("cannot find execve in /system/lib/libc.so");
        return -1;
    }
    if (registerInlineHook((uint32_t) execve_ptr, (uint32_t) new_execve, (uint32_t **) &old_execve) != ELE7EN_OK) {
        LOGD("Hook execve failed!");
        return -1;
    }
    if (inlineHook((uint32_t) execve_ptr) != ELE7EN_OK) {
        LOGD("Hook execve failed!");
        return -1;
    }
    // hook open memory
    void *openMem_ptr = findSymbol("/system/lib/libart.so",DexFileOpenMemory_fName);
    if(openMem_ptr == NULL){
        LOGD("cannot find %s in /system/lib/libart.so", DexFileOpenMemory_fName);
    }
    if (registerInlineHook((uint32_t) openMem_ptr, (uint32_t) new_DexFileOpenMemory, (uint32_t **) &old_DexFileOpenMemory) != ELE7EN_OK) {
        LOGD("Hook %s failed!", DexFileOpenMemory_fName);
        return -1;
    }
    if (inlineHook((uint32_t) openMem_ptr) != ELE7EN_OK) {
        LOGD("Hook %s failed!", DexFileOpenMemory_fName);
        return -1;
    }

	LOGD("finshed cs_hook");
    return 0;
}

int copyAssetToPath(JNIEnv *env, jobject context,const char *assetName, const char *path)
{

        jclass  context_class=(*env)->GetObjectClass(env,context);
        jmethodID getAssetsID=(*env)->GetMethodID(env, context_class, "getAssets", "()Landroid/content/res/AssetManager;");
        jobject assetManager = (*env)->CallObjectMethod(env,context,getAssetsID);
        AAssetManager* mgr = AAssetManager_fromJava(env, assetManager);
        AAsset* asset = AAssetManager_open(mgr, assetName, AASSET_MODE_UNKNOWN);
       if(asset==NULL)
       {
          LOGD("asset==NULL");
          return -1;
       }
       int bufferSize = AAsset_getLength(asset);
       LOGD("file size : %d\n",bufferSize);
       char *buffer=(char *)malloc(bufferSize+1);
       buffer[bufferSize]=0;
       int numBytesRead = AAsset_read(asset, buffer, bufferSize);
       AAsset_close(asset);
       FILE *fp = fopen(path, "wb+");
       if(fp==NULL)
       {
          LOGD("fp==NULL");
          return -1;
       }
       fwrite(buffer,sizeof(char), bufferSize, fp);
       fclose(fp);
       free(buffer);
       return 0;
}

int deleteFile(const char *path){
    LOGD("delete file");
    return remove(path);
}



int fix_dex(){
    LOGD("started dex fix");
    long base =  (long)dex_base;
    struct Header *header = (struct Header *)dex_base;
    mprotect(dex_base, header->file_size_, PROT_WRITE );

    long classDefs_off = header->class_defs_off_;
    long classDefs_size = header-> class_defs_size_;
    LOGD("classDefs_off:%x; classDefs_size:%d",classDefs_off,classDefs_size);
    struct ClassDef *classDefs = (struct ClassDef*)(base+classDefs_off);
    for (int i=0; i<classDefs_size; i++){
        long addr = base + classDefs[i].class_data_off_;
        if(classDefs[i].class_data_off_ <= 0 )
            continue;

        //getClassDataHeader
        struct ClassDataHeader *classDataHeader =(struct ClassDataHeader *)malloc(sizeof(struct ClassDataHeader));
        classDataHeader->static_fields_size_ = DecodeUnsignedLeb128(&addr);
        classDataHeader->instance_fields_size_ = DecodeUnsignedLeb128(&addr);
        classDataHeader->direct_methods_size_ = DecodeUnsignedLeb128(&addr);
        classDataHeader->virtual_methods_size_ = DecodeUnsignedLeb128(&addr);
        //parse fields
        LOGD("classdef[%d]:started parse fields:%d",i,classDataHeader->static_fields_size_ + classDataHeader->instance_fields_size_);

        for (int j = 0; j< classDataHeader->static_fields_size_ + classDataHeader->instance_fields_size_; j++)
        {
              struct ClassDataField *classDataField = (struct ClassDataField *)malloc(sizeof(struct ClassDataField));
              classDataField->field_idx_delta_ = DecodeUnsignedLeb128(&addr);
              classDataField->access_flags_ = DecodeUnsignedLeb128(&addr);
              free(classDataField);
        }
        //parse methods
        LOGD("classdef[%d]:started parse methods:%d",i ,classDataHeader->direct_methods_size_ + classDataHeader->virtual_methods_size_);
       for (int j = 0; j< classDataHeader->direct_methods_size_ + classDataHeader->virtual_methods_size_; j++)
        {
            struct ClassDataMethod *classDataMethod = (struct ClassDataMethod *)malloc(sizeof(struct ClassDataMethod));
            classDataMethod->method_idx_delta_ = DecodeUnsignedLeb128(&addr);
            classDataMethod->access_flags_ = DecodeUnsignedLeb128(&addr);
            classDataMethod->code_off_ = DecodeUnsignedLeb128(&addr);
            //fixcode start
             if(classDataMethod->code_off_<=0)
                continue;
            struct CodeItem* codeItem = (struct CodeItem *)(base + classDataMethod->code_off_);
            for(int k = 0 ;k < codeItem->insns_size_in_code_units_; k++)
            {
                LOGD("insns_[%d]:%d",k,codeItem->insns_[k]);
                codeItem->insns_[k] += 1;
            }
            LOGD("one pile of insns_ changed");
            free(classDataMethod);
        }
        free(classDataHeader);
    }

     LOGD("finished dex fix");

}

#define MODE_PRIVATE 0

JNICALL void
native_attachBaseContext(
        JNIEnv *env,
        jobject proxyApplication_obj,/* this */
        jobject mBase) {

        //super.attachBaseContext
        jclass proxyapplication_class = (*env)->GetObjectClass(env, proxyApplication_obj);
        jmethodID attachBaseContextID = (*env)->GetMethodID(env, APPLICATION_CLASS, "attachBaseContext", "(Landroid/content/Context;)V");
        (*env)->CallNonvirtualVoidMethod(env, proxyApplication_obj, APPLICATION_CLASS, attachBaseContextID, mBase);

        // init & create files
		LOGD("ProxyApplication: attachBaseContext started!");
        jmethodID getDirID = (*env)->GetMethodID(env, proxyapplication_class, "getDir", "(Ljava/lang/String;I)Ljava/io/File;");
        jobject file_odex_dir_obj= (*env)->CallObjectMethod(env, proxyApplication_obj, getDirID, (*env)->NewStringUTF(env, "odex"), MODE_PRIVATE);
        jobject file_dex_dir_obj = (*env)->CallObjectMethod(env, proxyApplication_obj, getDirID, (*env)->NewStringUTF(env, "dex"), MODE_PRIVATE);
        jobject file_lib_dir_obj = (*env)->CallObjectMethod(env, proxyApplication_obj, getDirID, (*env)->NewStringUTF(env, "lib"), MODE_PRIVATE);

        jmethodID getAbsolutePathID = (*env)->GetMethodID(env, (*env)->GetObjectClass(env, file_odex_dir_obj), "getAbsolutePath", "()Ljava/lang/String;");
        file_odex_dir_str =  (jstring)((*env)->CallObjectMethod(env, file_odex_dir_obj, getAbsolutePathID));
        odex_dir = (*env)->GetStringUTFChars(env, file_odex_dir_str, 0);
        LOGD("odex_dir:%s",odex_dir);
        file_dex_dir_str =  (jstring)((*env)->CallObjectMethod(env, file_dex_dir_obj, getAbsolutePathID));
        file_lib_dir_str =(jstring)((*env)->CallObjectMethod(env, file_lib_dir_obj, getAbsolutePathID));
        const char *dex_dir = (*env)->GetStringUTFChars(env, file_dex_dir_str, 0);
        //get dex_path
        char * str1 = (char *)malloc( 80 * sizeof(char));
        memset(str1,0,sizeof(char));
        strcat(str1,dex_dir);
        dex_path = strcat(str1,CLASSES_SUB_NAME);
        LOGD("dex_path:%s",dex_path);
        //get odex_path
        char * str2 = (char *)malloc( 80 * sizeof(char));
        memset(str2,0,sizeof(char));
        strcat(str2, odex_dir);
        odex_path = strcat(str2, CLASSES_SUB_NAME);
        LOGD("odex_path:%s",odex_path);
         //testcode
        //deleteFile(dex_path);
        if(access(dex_path,0))
        {
            LOGD("copy from assets");
            if(copyAssetToPath(env, proxyApplication_obj, CLASSES_NAME, dex_path))
            {
                    LOGD("copy dex file failed");
                    exit(-1);
                    return;
            }
        }

		if(cs_hook())
		{
			LOGD("hook failed");
			exit(-1);
			return;
		}



		
        currentActivityThreadID = (*env)->GetStaticMethodID(env, ACTIVITYTHREAD_CLASS, "currentActivityThread", "()Landroid/app/ActivityThread;");
		jmethodID getPackageNameID = (*env)->GetMethodID(env, (*env)->FindClass(env, "android/content/ContextWrapper"), "getPackageName","()Ljava/lang/String;");
		jstring packageName =  (*env)->CallObjectMethod(env, proxyApplication_obj, getPackageNameID);
		//get mPackages
		jfieldID mPackagesID = (*env)->GetFieldID(env, ACTIVITYTHREAD_CLASS, "mPackages", "Landroid/util/ArrayMap;");
		jobject mPackages = (*env)->GetObjectField(env, CURRENT_ACTIVITYTHREAD, mPackagesID);
		
		//get matched wr
		jmethodID getID_In_ArrayMap = (*env)->GetMethodID(env, (*env)->FindClass(env, "android/util/ArrayMap"), "get","(Ljava/lang/Object;)Ljava/lang/Object;");
		jobject wr = (*env)->CallObjectMethod(env, mPackages, getID_In_ArrayMap, packageName);
		
		//get loadedApk in weakreference
		jmethodID getID_In_WeakReference = (*env)->GetMethodID(env, (*env)->FindClass(env, "java/lang/ref/WeakReference"), "get","()Ljava/lang/Object;");
		jobject loadedApk = (*env)->CallObjectMethod(env, wr, getID_In_WeakReference, "get","()Landroid/app/LoadedApk;");
		
		//get classloader in loadedApk
		jfieldID  mClassloaderID = (*env)->GetFieldID(env, LOADEDAPK_CLASS, "mClassLoader", "Ljava/lang/ClassLoader;");
		jobject mClassloader = (*env)->GetObjectField(env, loadedApk, mClassloaderID);
		
		//new DexClassLoader(dex_path, odex_dir, dex_dir, mClassLoader)
		jmethodID initID = (*env)->GetMethodID(env, DEXCLASSLOADER_CLASS, "<init>","(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
		//params 3 need to fixme
		jobject newClassLoader=(*env)->NewObject(env, DEXCLASSLOADER_CLASS, initID, (*env)->NewStringUTF(env, dex_path), file_odex_dir_str, file_lib_dir_str, mClassloader);
		(*env)->SetObjectField(env, loadedApk, mClassloaderID, newClassLoader);
        //need to delete oat file
        //deleteOatFile(odex_path);

		jmethodID loadClassID = (*env)->GetMethodID(env, DEXCLASSLOADER_CLASS, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
		 jobject testClass = (*env)->CallObjectMethod(env, newClassLoader, loadClassID, (*env)->NewStringUTF(env, className));
        //fixme
        if(dex_base == NULL){
            LOGD("cannot get dex_base successfully");
            //fix dex
            exit(-1);
        }
		fix_dex();
		LOGD("AttachBaseContext finished!");

}

JNICALL void
native_onCreate(
        JNIEnv *env,
        jobject proxyApplication_obj/* this */) {
			
		LOGD("ProxyApplication: onCreate started!");
		//activityThread -> mBoundApplication -> info -> mApplication
		//               -> mInitialApplication
        //get activityThread

		//get mBoundApplication
		 jfieldID mBoundApplicationID = (*env)->GetFieldID(env, ACTIVITYTHREAD_CLASS, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;");
		 jobject mBoundApplication = (*env)->GetObjectField(env, CURRENT_ACTIVITYTHREAD, mBoundApplicationID);

		//get loadedapk
		jfieldID loadedApk_InfoID = (*env)->GetFieldID(env, APPBINDDATA_CLASS, "info", "Landroid/app/LoadedApk;");
		jobject loadedApk_Info = (*env)->GetObjectField(env, mBoundApplication, loadedApk_InfoID);
		
		//set mApplication null
		jfieldID mApplicationID = (*env)->GetFieldID(env, LOADEDAPK_CLASS, "mApplication", "Landroid/app/Application;");
		(*env)->SetObjectField(env, loadedApk_Info, mApplicationID, NULL);
		
		//get mInitialApplication
		jfieldID mInitialApplicationID =  (*env)->GetFieldID(env, ACTIVITYTHREAD_CLASS, "mInitialApplication","Landroid/app/Application;");
		jobject mInitialApplication = (*env)->GetObjectField(env, CURRENT_ACTIVITYTHREAD, mInitialApplicationID);
		oldApplication = mInitialApplication;
		oldApplication = (*env)->NewGlobalRef(env, oldApplication);

		//delete oldapplication
		jfieldID mAllApplicationsID = (*env)->GetFieldID(env, ACTIVITYTHREAD_CLASS, "mAllApplications", "Ljava/util/ArrayList;");
		jobject mAllApplications = (*env)->GetObjectField(env, CURRENT_ACTIVITYTHREAD, mAllApplicationsID);
	
		jclass arrayList_class = (*env)->FindClass(env, "java/util/ArrayList");
		jmethodID removeID =  (*env)->GetMethodID(env, arrayList_class, "remove", "(Ljava/lang/Object;)Z");
		(*env)->CallBooleanMethod(env, mAllApplications, removeID, oldApplication);
		
		
		//set className in appInfo and appBindData
		jfieldID appInfoID_In_LoadedApk = (*env)->GetFieldID(env, LOADEDAPK_CLASS, "mApplicationInfo", "Landroid/content/pm/ApplicationInfo;");
		jobject appInfo_In_LoadedApk = (*env)->GetObjectField(env, loadedApk_Info, appInfoID_In_LoadedApk);
		
		jfieldID appInfoID_In_AppBindData = (*env)->GetFieldID(env, APPBINDDATA_CLASS, "appInfo", "Landroid/content/pm/ApplicationInfo;");
		jobject appInfo_In_AppBindData = (*env)->GetObjectField(env, mBoundApplication, appInfoID_In_AppBindData);
		
		jfieldID classNameID = (*env)->GetFieldID(env, (*env)->FindClass(env,"android/content/pm/ApplicationInfo"), "className", "Ljava/lang/String;");
		//setValue fixme
		(*env)->SetObjectField(env, appInfo_In_LoadedApk, classNameID, (*env)->NewStringUTF(env, className));
		(*env)->SetObjectField(env, appInfo_In_AppBindData, classNameID, (*env)->NewStringUTF(env, className));
		jstring j = (*env)->GetObjectField(env, appInfo_In_LoadedApk, classNameID);
		jstring k = (*env)->GetObjectField(env, appInfo_In_AppBindData, classNameID);

		//call makeApplication
		jmethodID makeApplicationID = (*env)->GetMethodID(env, LOADEDAPK_CLASS, "makeApplication","(ZLandroid/app/Instrumentation;)Landroid/app/Application;");
		newApplication = (*env)->CallObjectMethod(env, loadedApk_Info, makeApplicationID, JNI_FALSE, NULL);
		//set newApplication
		(*env)->SetObjectField(env, CURRENT_ACTIVITYTHREAD, mInitialApplicationID, newApplication);
		
		//get mProviderMap 
		//jclass arrayMap_class = (*env)->FindClass(env, "android/util/ArrayMap");
		jfieldID mProviderMapID = (*env)->GetFieldID(env, ACTIVITYTHREAD_CLASS, "mProviderMap", "Landroid/util/ArrayMap;");
		jobject mProviderMap = (*env)->GetObjectField(env, CURRENT_ACTIVITYTHREAD, mProviderMapID);
		//get collection
		jmethodID valuesID = (*env)->GetMethodID(env, (*env)->FindClass(env,"android/util/ArrayMap"), "values", "()Ljava/util/Collection;");
		jobject collection = (*env)->CallObjectMethod(env, mProviderMap, valuesID);
		//get iterator
		jmethodID iteratorID = (*env)->GetMethodID(env, ((*env)->FindClass(env, "java/util/Collection")), "iterator", "()Ljava/util/Iterator;");
		jobject iterator = (*env)->CallObjectMethod(env, collection, iteratorID);

		//iterator.hasNext		
		jmethodID hasNextID = (*env)->GetMethodID(env, ITERATOR_CLASS, "hasNext", "()Z");
		jmethodID nextID = (*env)->GetMethodID(env, ITERATOR_CLASS, "next", "()Ljava/lang/Object;");
		jfieldID mLocalProviderID = (*env)->GetFieldID(env, (*env)->FindClass(env, "android/app/ActivityThread$ProviderClientRecord"), "mLocalProvider", "Landroid/content/ContentProvider;");
		jfieldID mContextID = (*env)->GetFieldID(env, (*env)->FindClass(env, "android/content/ContentProvider"), "mContext","Landroid/content/Context;");
		while((*env)->CallBooleanMethod(env, iterator, hasNextID)){
			//providerClientRecord = iterator.next
			jobject providerClientRecord = (*env)->CallObjectMethod(env, iterator, nextID);
			//get localProvider
			jobject localProvider = (*env)->GetObjectField(env, providerClientRecord, mLocalProviderID);
			//set new application
			(*env)->SetObjectField(env, localProvider, mContextID,newApplication);
		}





        LOGD("onCreate finished!");
		//newApplication.onCreate
		jmethodID onCreateID = (*env)->GetMethodID(env, APPLICATION_CLASS, "onCreate", "()V");
		(*env)->CallVoidMethod(env, newApplication, onCreateID);
		
}



static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods,
                                 int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == 0) {
        return JNI_FALSE;
    }

    LOGD("gMethods  %s,%s,%p\n ", gMethods[0].name, gMethods[0].signature, gMethods[0].fnPtr);

    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

static JNINativeMethod method_table[] = {
    {"attachBaseContext", "(Landroid/content/Context;)V", (void *) native_attachBaseContext},
    {"onCreate",          "()V",                          (void *) native_onCreate},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jint result = -1;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return result;
    }
    int status =  registerNativeMethods(env, JNIREG_CLASS, method_table, NELEM(method_table));
    if (!status) {
        LOGD("register call failed");
    }
    return JNI_VERSION_1_4;
}






