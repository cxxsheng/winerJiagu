package com.winer.parser;

import com.winer.debug.DbgLog;
import sun.misc.REException;

import java.io.*;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

public class AXMLParser {
    private byte[] xmlBytes;
    public AXMLFile  axmlFile = null;

    public byte[] getXmlBytes() {
        return xmlBytes;
    }

    public AXMLParser(byte[] bytes){
        xmlBytes = bytes;
    }


    public AXMLParser(String path){
        xmlBytes = Util.openFile(path);
    }


    public boolean parseAXML(){
        if (xmlBytes == null)
            return false;
        axmlFile = new AXMLFile();
        return parseHeader() && parseBody();
    }


    private String stringId2String(int nameId){
        List<String> stringsPool = axmlFile.mStrings.mStrings;
        // fixme
        String name = "@_@";
        if (nameId != 0xFFFFFFFF)
            name = stringsPool.get(nameId);
        return name;

    }

    private boolean changeRawValue(String tagName, String attrName, int id){
        for (int i = 0 ; i< axmlFile.nodes.size(); i++)
        {
            NodeChunk node = axmlFile.nodes.get(i);

            if (node.header.type == ResChunk_header.RES_XML_START_ELEMENT_TYPE)
            {
                ResXMLTree_attrExt attrExt = node.attrExt;
                if (stringId2String(attrExt.name).equals(tagName))

                    for (int j = 0; j < attrExt.attributes.size(); j++){
                        ResXMLTree_attribute attribute = attrExt.attributes.get(j);
                        if(stringId2String(attribute.name).equals(attrName))
                        {
                            node.setChangeFlag();
                            attribute.rawValue = id;
                            return true;
                        }
                    }
            }
        }
        DbgLog.dbgprint("Cannot find: "+tagName+"/"+attrName);
        return false;
    }
    public boolean modifyEntry(String entry){
        axmlFile.mHeader.setChangeFlag();
        axmlFile.mStrings.mHeader.setChangeFlag();
        byte[] headerBytes = axmlFile.mHeader.getBytes();
        int stringIndex = axmlFile.mStrings.addString(entry);

        if(stringIndex == -1){
            DbgLog.errPrint("addStr err!");
            return false;
        }

        if (!changeRawValue("application","name",stringIndex))
            return false;
        byte[] res = null;
        for (int i=0; i < axmlFile.chunks.size(); i++)
        {
            Chunk chunk = axmlFile.chunks.get(i);
            switch (chunk.header.type){
                case ResChunk_header.RES_STRING_POOL_TYPE:
                    res = Util.byteMerger(res, axmlFile.mStrings.getBytes());
                    break;
                default:
                    res = Util.byteMerger(res, (chunk).getBytes());
                    break;
            }
        }

        //changes size
        axmlFile.mHeader.header.size = headerBytes.length + res.length;
        headerBytes = axmlFile.mHeader.getBytes();
        res = Util.byteMerger(headerBytes, res);
        xmlBytes = res;

        this.parseAXML();
        return true;

    }


    public String getXmlString(){

        if (axmlFile == null)
        {
            DbgLog.errPrint("Pls parse fist!");
            return "";
        }
        List<NodeChunk> nodes = axmlFile.nodes;
        StringBuilder res = new StringBuilder();
        int lastTagId = 0;
        for (int i = 0; i < nodes.size(); i++)
        {
            NodeChunk chunk = nodes.get(i);
            switch (chunk.header.type)
            {
                case ResChunk_header.RES_XML_START_ELEMENT_TYPE:
                    res.append("<");
                    ResXMLTree_attrExt attrExt = chunk.attrExt;
                    int nameId = attrExt.name;
                    String tagName = stringId2String(nameId);
                    res.append(tagName + " ");
                    for (int j=0; j< chunk.attrExt.attributeCount; j++)
                    {
                        int attrNameId = attrExt.attributes.get(j).name;
                        int attrValueId =  attrExt.attributes.get(j).rawValue;
                        String attrTag = stringId2String(attrNameId);
                        String attrValue = stringId2String(attrValueId);
                        res.append( " "+attrTag + "=\"" + attrValue +"\"");
                    }
                    res.append(">");
                    lastTagId = nameId;
                    break;
                case ResChunk_header.RES_XML_END_ELEMENT_TYPE:
                    ResXMLTree_endElementExt endElementExt = chunk.endElementExt;
                    if (lastTagId == endElementExt.name) {
                        res.setCharAt(res.length()-1,'/');
                        res.append(">");
                    }
                    else
                        res.append("</" + stringId2String(endElementExt.name) +">");
                    break;

            }
        }
        return res.toString();
    }



    private static Chunk parseChunk(byte[] bytes){
        Chunk chunk = new Chunk();
        ResChunk_header mh = new ResChunk_header();
        byte[] type = Util.copyByte(bytes, 0, 2);
        byte[] headerSize = Util.copyByte(bytes, 2 ,2);
        byte[] size = Util.copyByte(bytes,4,4);

        mh.type = Util.byte2Short(type);
        mh.headerSize = Util.byte2Short(headerSize);
        mh.size = Util.byte2Int(size);
        chunk.originBytes = Util.copyByte(bytes, 0, mh.size);
        chunk.header = mh;
        return chunk;
    }

    public boolean  parseHeader(){
        Chunk header  = parseChunk(xmlBytes);
        header.setFileHeader(true);
        ResChunk_header mh = header.header;
        if (mh.type != ResChunk_header.RES_XML_TYPE || mh.size > xmlBytes.length)
            return false;
        axmlFile.mHeader = header;
        return true;
    }



    private boolean  parseStrings(int index, Chunk chunk){

        ResStringPool mStrings = new ResStringPool();
        mStrings.mHeader = new ResStringPool_header(chunk);
        byte[] stringCount = Util.copyByte(xmlBytes, index + ResChunk_header.size_, 4);
        byte[] styleCount = Util.copyByte(xmlBytes, index + ResChunk_header.size_ + 4, 4);
        byte[] flags = Util.copyByte(xmlBytes, index + ResChunk_header.size_ + 8, 4);
        byte[] stringsStart = Util.copyByte(xmlBytes, index + ResChunk_header.size_ + 12, 4);
        byte[] stylesStart = Util.copyByte(xmlBytes, index + ResChunk_header.size_ + 16, 4);

        mStrings.mHeader.stringCount = Util.byte2Int(stringCount);
        mStrings.mHeader.styleCount = Util.byte2Int(styleCount);
        mStrings.mHeader.flags = Util.byte2Int(flags);
        mStrings.mHeader.stringsStart = Util.byte2Int(stringsStart);
        mStrings.mHeader.stylesStart = Util.byte2Int(stylesStart);
        int charSize;
        if ((mStrings.mHeader.flags & ResStringPool_header.UTF8_FLAG) != 0 )
            charSize = 2;
        else
            charSize = 4;
        //parsestringids
        int stringIds[] = new int[mStrings.mHeader.stringCount];
        int stringIndex = chunk.header.headerSize + index;

        for (int i = 0; i< mStrings.mHeader.stringCount; i++)
        {
            byte[] id = Util.copyByte(xmlBytes, stringIndex, 4);
            stringIds[i] = Util.byte2Int(id);
            stringIndex += 4;
        }
        mStrings.stringIds = stringIds;
        //parse strings
        List<StringItem> strItems = new ArrayList<StringItem>();
        List<String> strings = new ArrayList<String>();
        for (int i = 0; i< mStrings.mHeader.stringCount; i++)
        {
            StringItem si = new StringItem();
            byte[] size = Util.copyByte(xmlBytes, index + mStrings.mHeader.stringsStart+ stringIds[i], 2);
            si.size = Util.byte2Short(size);
            si.string = Util.copyByte(xmlBytes , index + mStrings.mHeader.stringsStart+ stringIds[i] + 2, si.size * 2);
            //useless
            //si.end = xmlBytes[stringIndex+2+si.string.length];
            strItems.add(si);
            String str = Util.getString(xmlBytes, index + mStrings.mHeader.stringsStart+ stringIds[i], 2);
            strings.add(str);

        }
        mStrings.stringItems = strItems;
        mStrings.mStrings = strings;

        axmlFile.mStrings = mStrings;

        return true;
    }
    private boolean  parseResources(Chunk chunk) {
        return true;
    }
    private boolean valid_chunk(Chunk ch){
        return true;
    }

    private boolean parseNodes(int index, Chunk chunk) {
        NodeChunk nc = new NodeChunk(chunk);

        switch (chunk.header.type) {
            case ResChunk_header.RES_XML_START_NAMESPACE_TYPE:
            case ResChunk_header.RES_XML_END_NAMESPACE_TYPE:
                ResXMLTree_namespaceExt namespaceExt = new ResXMLTree_namespaceExt();
                byte[] prefix = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_, 4);
                byte[] uri = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 4, 4);
                namespaceExt.prefix = Util.byte2Int(prefix);
                namespaceExt.uri = Util.byte2Int(uri);
                nc.namespaceExt = namespaceExt;
                break;
            case ResChunk_header.RES_XML_START_ELEMENT_TYPE:
                ResXMLTree_attrExt attrExt = new ResXMLTree_attrExt();
                byte[] ns = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_, 4);
                byte[] name = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 4, 4);
                byte[] attributeStart = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 8, 2);
                byte[] attributeSize = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 10, 2);
                byte[] attributeCount = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_+ 12, 2);
                byte[] idIndex = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 14, 2);
                byte[] classIndex = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 16, 2);
                byte[] styleIndex = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ +18, 2);

                attrExt.ns = Util.byte2Int(ns);
                attrExt.name = Util.byte2Int(name);
                attrExt.attributeStart = Util.byte2Short(attributeStart);
                attrExt.attributeSize = Util.byte2Short(attributeSize);
                attrExt.attributeCount = Util.byte2Short(attributeCount);
                attrExt.idIndex = Util.byte2Short(idIndex);
                attrExt.classIndex = Util.byte2Short(classIndex);
                attrExt.styleIndex = Util.byte2Short(styleIndex);


                attrExt.attributes = parseAttributes(index + chunk.header.headerSize + attrExt.attributeStart, attrExt.attributeSize, attrExt.attributeCount);

                nc.attrExt = attrExt;
                //axmlFile.startTags.add(ra);
                break;
            case ResChunk_header.RES_XML_END_ELEMENT_TYPE:
                ResXMLTree_endElementExt endElementExt = new ResXMLTree_endElementExt();
                ns = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_, 4);
                name = Util.copyByte(xmlBytes, index + ResXMLTree_node.size_ + 4, 4);
                endElementExt.ns = Util.byte2Int(ns);
                endElementExt.name = Util.byte2Int(name);
                nc.endElementExt = endElementExt;
                break;
            case ResChunk_header.RES_XML_CDATA_TYPE:
                DbgLog.dbgprint("RES_XML_CDATA_TYPE");
                break;

        }
        axmlFile.nodes.add(nc);
        return true;
    }

    private List<ResXMLTree_attribute> parseAttributes(int offset, int size, int count) {
        List<ResXMLTree_attribute> res = new ArrayList<ResXMLTree_attribute>();
        int index = offset;
        for (int i = 0; i< count; i++){
            ResXMLTree_attribute ra = new ResXMLTree_attribute();
            byte[] ns = Util.copyByte(xmlBytes, index, 4);
            byte[] name = Util.copyByte(xmlBytes, index +4, 4);
            byte[] rawValue = Util.copyByte(xmlBytes, index + 8 , 4);
            byte[] valueSize = Util.copyByte(xmlBytes, index + 12, 2);

            ra.ns = Util.byte2Int(ns);
            ra.name = Util.byte2Int(name);
            ra.rawValue = Util.byte2Int(rawValue);
            ra.valueSize = Util.byte2Short(valueSize);
            ra.typedValue = Util.copyByte(xmlBytes, index+ 12, ra.valueSize);

            res.add(ra);
            index += size;
        }
        return res;
    }

    private boolean parseBody(){
        ResChunk_header header = axmlFile.mHeader.header;
        int end = header.size;
        int index = header.headerSize;
        Chunk chunk =parseChunk(Util.copyByte(xmlBytes, header.headerSize, end-index));
        List<Chunk> chunks = new ArrayList();
        while (index < (end - chunk.header.headerSize) && index < (end - ResChunk_header.size_))
        {

            chunk = parseChunk(Util.copyByte(xmlBytes, index, end-index));
            if (!valid_chunk(chunk))
                return false;
            short type = chunk.header.type;
            int size = chunk.header.size;
            if (type == ResChunk_header.RES_STRING_POOL_TYPE)
            {
                if (!parseStrings(index , chunk))
                {
                   DbgLog.errPrint("parseStrings err!");
                   return false;
                }
                chunks.add(axmlFile.mStrings.mHeader);
            }
            else if(type == ResChunk_header.RES_XML_RESOURCE_MAP_TYPE)
            {
                if (!parseResources(chunk))
                {
                    DbgLog.errPrint("parseStrings err!");
                    return false;
                }
                chunks.add(chunk);
            }
            else if (type >= ResChunk_header.RES_XML_FIRST_CHUNK_TYPE
                    && type <= ResChunk_header.RES_XML_LAST_CHUNK_TYPE)
            {
                if (!parseNodes(index, chunk)){
                    DbgLog.errPrint("parseStrings err!");
                    return false;
                }
                chunks.add(axmlFile.nodes.get(axmlFile.nodes.size()-1));

            }else {

                chunks.add(chunk);
                DbgLog.dbgprint("Useless chunk type: "+ chunk.header.type);
            }
            index += size;
        }
        axmlFile.chunks = chunks;
        return true;
    }
    public boolean writeToFile(String path){
        FileOutputStream fop = null;
        File file;

        try {

            file = new File(path);
            fop = new FileOutputStream(file);

            // if file doesnt exists, then create it
            if (!file.exists()) {
                file.createNewFile();
            }

            // get the content in bytes

            fop.write(xmlBytes);
            fop.flush();
            fop.close();


        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fop != null) {
                    fop.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return true;
    }
}


