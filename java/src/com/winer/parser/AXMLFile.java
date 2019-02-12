/*
9/1/2019
Translate from /frameworks/base/include/androidfw/ResourceTypes.h by winer.
*/

package com.winer.parser;

import com.winer.debug.DbgLog;

import java.util.ArrayList;
import java.util.List;

public class AXMLFile {
    public Chunk mHeader;
    public List<Chunk> chunks;
    public int                      mSize;
    //const uint8_t*              mDataEnd;
    public ResStringPool               mStrings;
    //    byte[]             mResIds;
    //    int                      mNumResIds;
    // ResXMLTree_node      mRootNode;
    //  const void*                  mRootExt;
    //int                mRootCode;
    public List<NodeChunk> nodes = new ArrayList();

}
class Chunk{
    public ResChunk_header header;
    public byte[] originBytes;
    boolean changeFlag = false;
    private boolean isFileHeader = false;
    public byte[] getBytes() {
        if (changeFlag || isFileHeader)
            return header.getBytes();
        if (isFileHeader)
            return Util.copyByte(originBytes,0,header.headerSize);

        return originBytes;
    }

    public void setChangeFlag() {
        this.changeFlag = true;
    }

    public void setFileHeader(boolean fileHeader) {
        isFileHeader = fileHeader;
    }

    public Chunk(){

    }
    public Chunk(Chunk chunk){
        this.header = chunk.header;
        this.originBytes = chunk.originBytes;
    }
}
class NodeChunk extends Chunk
{
    public int lineNumber = 0;
    public int comment = -1;
    public ResXMLTree_namespaceExt namespaceExt = null;
    public ResXMLTree_attrExt attrExt = null;
    public ResXMLTree_endElementExt endElementExt = null;

    public NodeChunk(Chunk chunk) {
        super(chunk);
    }

    @Override
    public byte[] getBytes(){
        if (changeFlag)
            return getChangedBytes();
        else
            return originBytes;
    }
    public byte[] getChangedBytes(){
        byte[] res = header.getBytes();
        res = Util.byteMerger(res, Util.int2Byte(lineNumber));
        res = Util.byteMerger(res, Util.int2Byte(comment));
        switch (header.type){
            case ResChunk_header.RES_XML_START_NAMESPACE_TYPE:
            case ResChunk_header.RES_XML_END_NAMESPACE_TYPE:
                res = Util.byteMerger(res, namespaceExt.getBytes());
                break;
            case ResChunk_header.RES_XML_START_ELEMENT_TYPE:
                res = Util.byteMerger(res, attrExt.getBytes());
                break;
            case ResChunk_header.RES_XML_END_ELEMENT_TYPE:
                res = Util.byteMerger(res, endElementExt.getBytes());
                break;
            case ResChunk_header.RES_XML_CDATA_TYPE:
                DbgLog.dbgprint("RES_XML_CDATA_TYPE");
                break;
        }
        return res;
    }

}

class   ResChunk_header
{
        final static public int size_ = 2+2+4;
        final public static short RES_NULL_TYPE               = 0x0000;
        final public static short RES_STRING_POOL_TYPE        = 0x0001;
        final public static short RES_TABLE_TYPE              = 0x0002;
        final public static short RES_XML_TYPE                = 0x0003;

        // Chunk types in RES_XML_TYPE
        final public static short RES_XML_FIRST_CHUNK_TYPE    = 0x0100;
        final public static short RES_XML_START_NAMESPACE_TYPE= 0x0100;
        final public static short RES_XML_END_NAMESPACE_TYPE  = 0x0101;
        final public static short RES_XML_START_ELEMENT_TYPE  = 0x0102;
        final public static short RES_XML_END_ELEMENT_TYPE    = 0x0103;
        final public static short RES_XML_CDATA_TYPE          = 0x0104;
        final public static short RES_XML_LAST_CHUNK_TYPE     = 0x017f;
        // This contains a uint32_t array mapping strings in the string
        // pool back to resource identifiers.  It is optional.
        final public static short RES_XML_RESOURCE_MAP_TYPE   = 0x0180;

        // Chunk types in RES_TABLE_TYPE
        final public static short RES_TABLE_PACKAGE_TYPE      = 0x0200;
        final public static short RES_TABLE_TYPE_TYPE         = 0x0201;
        final public static short RES_TABLE_TYPE_SPEC_TYPE    = 0x0202;
        final public static short RES_TABLE_LIBRARY_TYPE      = 0x0203;

         // Type identifier for this chunk.  The meaning of this value depends
        // on the containing chunk.
        public short type;

        // Size of the chunk header (in bytes).  Adding this value to
        // the address of the chunk allows you to find its associated data
        // (if any).
        public short headerSize;

        // Total size of this chunk (in bytes).  This is the chunkSize plus
        // the size of any data associated with the chunk.  Adding this value
        // to the chunk allows you to completely skip its contents (including
        // any child chunks).  If this value is the same as chunkSize, there is
        // no data associated with the chunk.
        public int size;

        public byte[] getBytes(){
            byte[] res;
            res = Util.short2Byte(type);
            res = Util.byteMerger(res, Util.short2Byte(headerSize));
            res = Util.byteMerger(res, Util.int2Byte(size));
            return res;
        }
};


/**
 * Basic XML tree node.  A single item in the XML document.  Extended info
 * about the node can be found after header.headerSize.
 */
// fixme
class ResXMLTree_node
{

        public static int size_ = ResChunk_header.size_ + 4 + 4;

        public ResChunk_header header;

        // Line number in original source file at which this element appeared.
        public int lineNumber;

        // Optional XML comment that was associated with this element; -1 if none.
        public int comment;
        byte[] getBytes(){
            byte[] res = header.getBytes();
            res = Util.byteMerger(res, Util.int2Byte(lineNumber));
            res = Util.byteMerger(res, Util.int2Byte(comment));
            return res;
        }
};

/**
 * Extended XML tree node for CDATA tags -- includes the CDATA string.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
class ResXMLTree_cdataExt
{
        // The raw CDATA character data.
        int data;

        // The typed value of the character data if this is a CDATA node.
        //Res_value typedData;
};

/**
 * Extended XML tree node for namespace start/end nodes.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
class ResXMLTree_namespaceExt
{
        // The prefix of the namespace.
        int prefix;

        // The URI of the namespace.
        int uri;

        public byte[] getBytes(){
            return Util.byteMerger(Util.int2Byte(prefix),Util.int2Byte(uri));
        }
};

/**
 * Extended XML tree node for element start/end nodes.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
class ResXMLTree_endElementExt
{
        // String of the full namespace of this element.
         int ns;

        // String name of this node if it is an ELEMENT; the raw
        // character data if this is a CDATA node.
         int name;


        public byte[] getBytes(){
            return Util.byteMerger(Util.int2Byte(ns),Util.int2Byte(name));
        }
};

/**
 * Extended XML tree node for start tags -- includes attribute
 * information.
 * Appears header.headerSize bytes after a ResXMLTree_node.
 */
class ResXMLTree_attrExt
{
        // String of the full namespace of this element.
        int ns;

        // String name of this node if it is an ELEMENT; the raw
        // character data if this is a CDATA node.
        public int name;

        // Byte offset from the start of this structure where the attributes start.
        public short attributeStart;

        // Size of the ResXMLTree_attribute structures that follow.
        public short attributeSize;

        // Number of attributes associated with an ELEMENT.  These are
        // available as an array of ResXMLTree_attribute structures
        // immediately following this node.
        public short attributeCount;

        // Index (1-based) of the "id" attribute. 0 if none.
        public short idIndex;

        // Index (1-based) of the "class" attribute. 0 if none.
        public short classIndex;

        // Index (1-based) of the "style" attribute. 0 if none.
        public short styleIndex;

        public List<ResXMLTree_attribute> attributes;

        public byte[] getBytes(){
            byte[] res = Util.int2Byte(ns);
            res = Util.byteMerger(res, Util.int2Byte(name));
            res = Util.byteMerger(res, Util.short2Byte(attributeStart));
            res = Util.byteMerger(res, Util.short2Byte(attributeSize));
            res = Util.byteMerger(res, Util.short2Byte(attributeCount));
            res = Util.byteMerger(res, Util.short2Byte(idIndex));
            res = Util.byteMerger(res, Util.short2Byte(classIndex));
            res = Util.byteMerger(res, Util.short2Byte(styleIndex));
            for(int i = 0; i < attributeCount; i++)
                res = Util.byteMerger(res , attributes.get(i).getBytes());

            return res;

        }

};

class ResXMLTree_attribute
{
        // Namespace of this attribute.
         public int ns;

        // Name of this attribute.
         public int name;

        // The original raw string value of this attribute.
         public int rawValue;

        // Processesd typed value of this attribute.

        public short valueSize;

        public int data;

        public byte[] typedValue;

        public byte[] getBytes(){
            byte[] res = Util.int2Byte(ns);
            res = Util.byteMerger(res, Util.int2Byte(name));
            res = Util.byteMerger(res, Util.int2Byte(rawValue));
            res = Util.byteMerger(res, typedValue);
            return res;
        }
};

class ResStringPool_header extends Chunk
{


        //public ResChunk_header header;
        // Number of strings in this pool (number of uint32_t indices that follow
        // in the data).
        public int stringCount;
        // Number of style span arrays in the pool (number of uint32_t indices
        // follow the string indices).
        public int styleCount;
        // Flags.
        // If set, the string index is sorted by the string values (based
        // on strcmp16()).
        public  static int SORTED_FLAG = 1 << 0;
        // String pool is encoded in UTF-8
        public  static int UTF8_FLAG = 1<< 8;
        public int flags;
        // Index from header of the string data.
        public int stringsStart;
        // Index from header of the style data.
        public int stylesStart;

        public ResStringPool_header(Chunk chunk) {
            super(chunk);
        }

        @Override
        public byte[] getBytes(){
            byte[] res = super.getBytes();
            res = Util.byteMerger(res, Util.int2Byte(stringCount));
            res = Util.byteMerger(res, Util.int2Byte(styleCount));
            res = Util.byteMerger(res, Util.int2Byte(flags));
            res = Util.byteMerger(res, Util.int2Byte(stringsStart));
            res = Util.byteMerger(res, Util.int2Byte(stylesStart));
            return res;
        }

};

class ResStringPool
{
        //status_t                    mError;
        //void*                       mOwnedData;

        public ResStringPool_header mHeader;
        //public int                      mSize;
        //mutable Mutex               mDecodeLock;
        //public int             mEntries;
        //public int             mEntryStyles;
        public int[] stringIds;

        public List<StringItem> stringItems;
        //char16_t mutable**          mCache;
        //public int                    mStringPoolSize;    // number of uint16_t
        //const uint32_t*             mStyles;
        //public int                    mStylePoolSize;    // number of uint32_t
        public List<String>  mStrings;


        public int addString(String str) {
            mHeader.setChangeFlag();
            mStrings.add(str);
            mHeader.stringCount += 1;

            StringItem newItem = new StringItem();
            try
            {
                newItem.string = str.getBytes("UTF-16LE");
                // delete 0xffff or 0xfeff(utf-16's prefix)
                //newItem.string = Util.copyByte(newItem.string, 2,newItem.string.length - 2);
            }catch (Exception e){
                DbgLog.errPrint("Invalid utf-16 str:"+str);
                return -1;
            }
            newItem.size = (short) (str.length());
            stringItems.add(newItem);
            // wait to change
            stringIds = new int[stringIds.length+1];
            mHeader.header.size = 0;
            mHeader.stringsStart= 0;

            return mHeader.stringCount - 1;
        }

        public byte[] getBytes(){
            getBytes_();
            return getBytes_();
        }
        private byte[] getBytes_() {
            byte[] res = mHeader.getBytes();

            for (int i = 0; i < mHeader.stringCount; i++)
                res = Util.byteMerger(res, Util.int2Byte(stringIds[i]));
            mHeader.stringsStart = res.length;
            for (int i = 0; i < mHeader.stringCount; i++){
                stringIds[i] = res.length - mHeader.stringsStart;
                res = Util.byteMerger(res, stringItems.get(i).getBytes());
            }
            mHeader.header.size = res.length;
            return res;
        }

}



//class ResStringPool_ref
//{
//        // Index into the string pool table (uint32_t-offset from the indices
//        // immediately after ResStringPool_header) at which to find the location
//        // of the string data in the pool.
//        public int index;
//};


class StringItem
{
        public short size;
        public byte[] string;
        public short end = 0;
        public int getSize(){
                return 2 + size*2 +2;
        }
        public byte[] getBytes(){
            byte[] res = Util.short2Byte(size);
            res = Util.byteMerger(res, string);
            res = Util.byteMerger(res,Util.short2Byte(end));
            return res;
        }
}
