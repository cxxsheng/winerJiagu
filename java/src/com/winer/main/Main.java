package com.winer.main;

import com.winer.debug.DbgLog;
import com.winer.parser.AXMLParser;
import com.winer.parser.ApkParser;
import com.winer.parser.DexParser;

import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.CommandLine;

public class Main {
    static String input;//="C:\\Users\\Administrator\\Desktop\\aijiami\\task-TryGetFlag_02_D45L2DW.apk";
    static String output;//="C:\\Users\\Administrator\\Desktop\\binjiang";
    static String dataPath;
    static String binDir = "C:/Users/Administrator/Desktop/bin";
    static String shellPath = binDir + "/classes.dex";
    static String soPath = binDir +"/libplsHelpMe.so";
    public static void main(String[] args) throws Exception {
        System.out.println(System.getProperty("user.dir"));
        CommandLineParser parser = new BasicParser( );
        Options options = new Options();
        options.addOption("h", "help", false, "Print this usage information");
        options.addOption("i","input",true, "Raw apk file's needed to pack");
        options.addOption("o","output",true, "Output dir");

        CommandLine commandLine = parser.parse(options, args);
        // Set the appropriate variables based on supplied options
        if( commandLine.hasOption('h') ) {
            System.out.println("-h:help Print this usage information\n" +
                                "-i:input Raw apk file's needed to pack\n" +
                                 "-o:output dir");
            System.exit(0);
        }
        if( commandLine.hasOption('i') && commandLine.hasOption('o') ) {
            input = commandLine.getOptionValue('i');
            output = commandLine.getOptionValue('o');
        }//fixme
        else {
            System.out.println(options.toString());
            System.exit(1);
        }


        ApkParser apkParser = new ApkParser(input, output);
        String mainifest =  apkParser.extractManifest();
        String dexFile  = apkParser.extractDex();

        //modify entry
        AXMLParser axmlParser = new AXMLParser(mainifest);
        if (!axmlParser.parseAXML() || !axmlParser.modifyEntry("com.winer.proxyapp.ProxyApplication"))
        {
            DbgLog.errPrint("Axml cannot be modified!");
            return;
        }

        DbgLog.dbgprint(axmlParser.getXmlString());
        byte[] axmlData = axmlParser.getXmlBytes();

        //encrypt dex data
        DexParser dexParser = new DexParser(dexFile);
        if (!dexParser.parseDex() || !dexParser.encryptAllMethods()){
            DbgLog.errPrint("Dex cannot be modified!");
            return;
        }
        byte[] dexData = dexParser.getDexBytes();


        apkParser.injectAll(shellPath, soPath, axmlData, dexData);



    }





}

