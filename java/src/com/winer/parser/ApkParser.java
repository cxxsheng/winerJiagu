package com.winer.parser;

import org.zeroturnaround.zip.ZipUtil;

import java.io.*;

public class ApkParser {
    private String apkPath;
    private String outPutPath;
    private File apkFile;
    private File originApk;
    private File swap=new File(outPutPath+"swap.bin");;
    public ApkParser(String apkPath, String outPutPath) throws IOException {
        this.apkPath = apkPath;
        this.outPutPath = outPutPath;
        this.originApk = new File(apkPath);
        this.apkFile  = new File(outPutPath+"/jiagu.apk");
        copyFileUsingFileStreams(originApk,apkFile);
    }

    private static void copyFileUsingFileStreams(File source, File dest)
            throws IOException {
        InputStream input = null;
        OutputStream output = null;
        try {
            input = new FileInputStream(source);
            output = new FileOutputStream(dest);
            byte[] buf = new byte[1024];
            int bytesRead;
            while ((bytesRead = input.read(buf)) > 0) {
                output.write(buf, 0, bytesRead);
            }
        } finally {
            input.close();
            output.close();
        }
    }


    private void myAddEntry(File zip, String path, File file, File destZip){
        ZipUtil.addEntry(zip, path, file, swap);
        try {
            copyFileUsingFileStreams(swap, destZip);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (!swap.getName().equals(destZip.getName()))
            swap.delete();
    }

    private void myAddEntry(File zip, String path, byte[] bytes, File destZip){
        ZipUtil.addEntry(zip, path,bytes, swap);
        try {
            copyFileUsingFileStreams(swap, destZip);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (!swap.getName().equals(destZip.getName()))
            swap.delete();
    }
    public String extractManifest(){
        if (!ZipUtil.unpackEntry(apkFile, "AndroidManifest.xml", new File(outPutPath+"/AndroidManifest.xml")))
            return null;
        return outPutPath+"/AndroidManifest.xml";
    }
    public String extractDex(){
        if (!ZipUtil.unpackEntry(apkFile, "classes.dex", new File(outPutPath+"/classes.dex")))
            return null;
        return outPutPath+"/classes.dex";
    }

    private void injectShellDex(String path){
        ZipUtil.removeEntry(apkFile, "classes.dex");
        myAddEntry(apkFile, "classes.dex", new File(path), apkFile);
    }
    private void injectSo(String path) {
        myAddEntry(apkFile, "lib/armeabi-v7a/libplsHelpMe.so", new File(path), apkFile);
        myAddEntry(apkFile, "lib/armeabi/libplsHelpMe.so", new File(path), apkFile);
    }


    private void injectManifest(byte[] manifestBytes){
        ZipUtil.removeEntry(apkFile, "AndroidManifest.xml");
        myAddEntry(apkFile, "AndroidManifest.xml", manifestBytes, apkFile);
    }

    private void injectRealDex(byte[] dexBytes){
        myAddEntry(apkFile, "assets/classes2.dex", dexBytes, apkFile);
    }

    public void injectAll(String shellPath, String soPath, byte[] axmlBytes, byte[] realDexBytes){
        injectShellDex(shellPath);
        injectSo(soPath);
        injectManifest(axmlBytes);
        injectRealDex(realDexBytes);
    }
}
