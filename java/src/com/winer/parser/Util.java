package com.winer.parser;

import com.winer.debug.DbgLog;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;

public class Util {

    public static void byteCover(byte[] coveree, byte[] coverer, int offset){
        if (coveree == null || coverer == null)
            return;
        if (coveree.length < coverer.length + offset)
            return;
        for (int i = 0; i < coverer.length; i++)
            coveree[i+offset] = coverer[i];
    }

    public static byte[] byteMerger(byte[] bt1, byte[] bt2){
        if (bt1==null)
            return bt2;
        if (bt2 == null)
            return bt1;

        byte[] bt3 = new byte[bt1.length+bt2.length];
        for (int i=0;i <  bt3.length;i++)
            if (i<bt1.length)
                bt3[i] = bt1[i];
            else
                bt3[i]= bt2[i-bt1.length];
        return bt3;
    }

    public static byte[] copyByte(byte[] src, int start, int len){
        if(src == null){
            return null;
        }
        if(start > src.length){
            return null;
        }
        if((start+len) > src.length){
            return null;
        }
        if(start<0){
            return null;
        }
        if(len<=0){
            return null;
        }
        byte[] resultByte = new byte[len];
        for(int i=0;i<len;i++){
            resultByte[i] = src[i+start];
        }
        return resultByte;
    }

    public static int byte2Int(byte[] res) {
        return (res[0] & 0xff) | ((res[1] << 8) & 0xff00)
                | ((res[2] << 24) >>> 8) | (res[3] << 24);
    }

    public static byte[] int2Byte(int n) {
        byte[] b = new byte[4];
        b[0] = (byte) (n & 0xff);
        b[1] = (byte) (n >> 8 & 0xff);
        b[2] = (byte) (n >> 16 & 0xff);
        b[3] = (byte) (n >> 24 & 0xff);
        return b;
    }

    public static byte[] short2Byte(short number) {
        int temp = number;
        byte[] b = new byte[2];
        for (int i = 0; i < b.length; i++) {
            b[i] = new Integer(temp & 0xff).byteValue();
            temp = temp >> 8;
        }
        return b;
    }

    public static short byte2Short(byte[] b) {
        short s = 0;
        short s0 = (short) (b[0] & 0xff);
        short s1 = (short) (b[1] & 0xff);
        s1 <<= 8;
        s = (short) (s0 | s1);
        return s;
    }

    public static String bytesToHexString(byte[] src){
        //byte[] src = reverseBytes(src1);
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv+" ");
        }
        return stringBuilder.toString();
    }

//    public static char[] getChars(byte[] bytes) {
//        Charset cs = Charset.forName ("UTF-8");
//        ByteBuffer bb = ByteBuffer.allocate (bytes.length);
//        bb.put (bytes);
//        bb.flip ();
//        CharBuffer cb = cs.decode (bb);
//        return cb.array();
//    }

    public static   String getString(byte[] bs, int index, int size){
        int len = bs[index] * size;
        byte[] b = Util.copyByte(bs, 1+index, len);
        String result = "";
        if (b==null){
            return result;
        }
        try{
            if (size==1)
                result = new String(b, "UTF-8");
            else if (size==2)
                result = new String(b, "UTF-16");

        }catch(Exception e){
            DbgLog.errPrint("Str parsed err!");
            return  "masaik3";
        }

        return result;
    }
    public static byte[] readUnsignedLeb128(byte[] srcByte, int offset){
        List<Byte> byteAryList = new ArrayList<Byte>();
        byte bytes = Util.copyByte(srcByte, offset, 1)[0];
        byte highBit = (byte)(bytes & 0x80);
        byteAryList.add(bytes);
        offset ++;
        while(highBit != 0){
            bytes = Util.copyByte(srcByte, offset, 1)[0];
            highBit = (byte)(bytes & 0x80);
            offset ++;
            byteAryList.add(bytes);
        }
        byte[] byteAry = new byte[byteAryList.size()];
        for(int j=0;j<byteAryList.size();j++){
            byteAry[j] = byteAryList.get(j);
        }
        return byteAry;
    }

    /**
     * 解码leb128数据
     * 每个字节去除最高位，然后进行拼接，重新构造一个int类型数值，从低位开始
     * @param byteAry
     * @return
     */
    public static int decodeUleb128(byte[] byteAry) {
        int index = 0, cur;
        int result = byteAry[index];
        index++;

        if(byteAry.length == 1){
            return result;
        }
        cur = byteAry[index];
        index++;
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if(byteAry.length == 2){

            return result;
        }
        cur = byteAry[index];
        index++;
        result |= (cur & 0x7f) << 14;
        if(byteAry.length == 3){

            return result;
        }
        cur = byteAry[index];
        index++;
        result |= (cur & 0x7f) << 21;
        if(byteAry.length == 4){

            return result;
        }
        cur = byteAry[index];
        index++;
        result |= cur << 28;

        if(byteAry.length == 5){
            return result;
        }
        return result;
    }

    public   static byte[] openFile(String path){
        byte[] srcByte = null;
        FileInputStream fis = null;
        ByteArrayOutputStream bos = null;
        try{
            fis = new FileInputStream(path);
            bos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len = 0;
            while((len=fis.read(buffer)) != -1){
                bos.write(buffer, 0, len);
            }
            srcByte = bos.toByteArray();
        }catch(Exception e){
            System.out.println("read res file error:"+e.toString());
            return null;
        }finally{
            try{
                fis.close();
                bos.close();
            }catch(Exception e){
                System.out.println("close file error:"+e.toString());
            }
        }
        return srcByte;
    }
}
