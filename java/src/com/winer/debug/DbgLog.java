package com.winer.debug;

public class DbgLog {
    final static private boolean  isDebug = true;
    static public void dbgprint(String str){
        if (isDebug)
            System.out.println(str);
    }
    static public void errPrint(String info){
        System.out.println("Error:  "+info);
    }
}
