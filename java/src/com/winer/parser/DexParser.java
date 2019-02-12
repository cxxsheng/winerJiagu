

package com.winer.parser;

import com.sun.org.apache.bcel.internal.classfile.Code;
import com.winer.debug.DbgLog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.zip.Adler32;


public class DexParser {
    private byte[] dexBytes;
    public DexFile dexFile ;

    public DexParser(byte[] bytes) {
        dexBytes = bytes;
    }

    public DexParser(String path){
        dexBytes = Util.openFile(path);
    }

    public byte[] getDexBytes() {
        return dexBytes;
    }

    public boolean parseDex() {

        if (dexBytes == null)
            return false;

        dexFile = new DexFile();
        boolean ret =  parseDexHeader() && parseMapItems() &&
                        parseStringIds() && parseStrings() &&
                        parseTypeItems() && parseProtoIds() &&
                        parseFieldIds() && parseMethodIds() &&
                        parseClassDefs() && parseClassDatas() &&
                        parseCode();
        if (ret)
            DbgLog.dbgprint("gery vood");
        return ret;
    }
    private boolean parseDexHeader() {
        DexHeader header = new DexHeader(0 , 0);
        header.magic = Util.copyByte(dexBytes, 0, 8);
        if (dexBytes.length <= DexHeader.size) {
            DbgLog.errPrint("bytes is too short!");
            return false;
        }
        if (header.magic == null ||
                !Arrays.equals(header.magic, Util.byteMerger(DexHeader.kDexMagic, DexHeader.kDexMagicVersion))) {
            DbgLog.errPrint("magic is not valid!");
            return false;
        }
        header.checksum_ = Util.byte2Int(Util.copyByte(dexBytes, 8, 4));
        header.signature_ = Util.copyByte(dexBytes, 12, 20);
        header.file_size_ = Util.byte2Int(Util.copyByte(dexBytes, 32, 4));
        if (header.file_size_ > dexBytes.length) {
            DbgLog.errPrint("It is not the whole dexfile!");
            return false;
        }
        header.header_size_ = Util.byte2Int(Util.copyByte(dexBytes, 36, 4));
        header.endian_tag_ = Util.byte2Int(Util.copyByte(dexBytes, 40, 4));
        header.link_size_ = Util.byte2Int(Util.copyByte(dexBytes, 44, 4));
        header.link_off_ = Util.byte2Int(Util.copyByte(dexBytes, 48, 4));
        header.map_off_ = Util.byte2Int(Util.copyByte(dexBytes, 52, 4));
        header.string_ids_size_ = Util.byte2Int(Util.copyByte(dexBytes, 56, 4));
        header.string_ids_off_ = Util.byte2Int(Util.copyByte(dexBytes, 60, 4));
        header.type_ids_size_ = Util.byte2Int(Util.copyByte(dexBytes, 64, 4));
        header.type_ids_off_ = Util.byte2Int(Util.copyByte(dexBytes, 68, 4));
        header.proto_ids_size_ = Util.byte2Int(Util.copyByte(dexBytes, 72, 4));
        header.proto_ids_off_ = Util.byte2Int(Util.copyByte(dexBytes, 76, 4));
        header.field_ids_size_ = Util.byte2Int(Util.copyByte(dexBytes, 80, 4));
        header.field_ids_off_ = Util.byte2Int(Util.copyByte(dexBytes, 84, 4));
        header.method_ids_size_ = Util.byte2Int(Util.copyByte(dexBytes, 88, 4));
        header.method_ids_off_ = Util.byte2Int(Util.copyByte(dexBytes, 92, 4));
        header.class_defs_size_ = Util.byte2Int(Util.copyByte(dexBytes, 96, 4));
        header.class_defs_off_ = Util.byte2Int(Util.copyByte(dexBytes, 100, 4));
        header.data_size_ = Util.byte2Int(Util.copyByte(dexBytes, 104, 4));
        header.data_off_ = Util.byte2Int(Util.copyByte(dexBytes, 108, 4));
        dexFile.dexHeader_ = header;
        header.dataSize = header.header_size_;
        return true;

    }


    private boolean parseMapItems(){
        DexHeader header = dexFile.dexHeader_;
        byte[] mapSizeBs = Util.copyByte(dexBytes, header.map_off_, 4);
        int mapSize = Util.byte2Int(mapSizeBs);
        List<MapItem> mapItemsList = new ArrayList<MapItem>();
        for (int i = 0; i < mapSize; i++)
        {
            int base = MapItem.size * i;
            MapItem mapItem = new MapItem(base, MapItem.size);
            byte[] type_ = Util.copyByte(dexBytes, header.map_off_ + base + 4, 2);
            byte[] unused_ = Util.copyByte(dexBytes, header.map_off_ + base + 6, 2);
            byte[] size_ = Util.copyByte(dexBytes, header.map_off_ + base + 8, 4);
            byte[] offset_ = Util.copyByte(dexBytes, header.map_off_ + base + 12, 4);
            mapItem.type_ = Util.byte2Short(type_);
            mapItem.unused_ = Util.byte2Short(unused_);
            mapItem.size_ = Util.byte2Int(size_);
            mapItem.offset_ = Util.byte2Int(offset_);

            mapItemsList.add(mapItem);
        }
        dexFile.mapItemsList = mapItemsList;
        return true;
    }

    private boolean parseStringIds() {
        DexHeader header = dexFile.dexHeader_;
        List<StringId> stringIdsList = new ArrayList<StringId>();

        for (int i = 0; i < header.string_ids_size_;i++){
            int base = header.string_ids_off_ + StringId.size * i;
            StringId stringId = new StringId(base, StringId.size);
            byte[] bs = Util.copyByte(dexBytes, base , StringId.size);
            stringId.string_data_off_ = Util.byte2Int(bs);
            stringIdsList.add(stringId);
        }
        dexFile.stringIdsList = stringIdsList;
        return true;
    }

    private boolean parseStrings(){
        DexHeader header = dexFile.dexHeader_;
        List<String> stringsList = new ArrayList<String>();
        for (int i = 0; i < header.string_ids_size_;i++) {
            int index = dexFile.stringIdsList.get(i).string_data_off_;
            String s = Util.getString(dexBytes, index, 1);
            stringsList.add(s);
        }
        dexFile.stringsList = stringsList;
        return  true;
    }

    private boolean parseTypeItems(){
        DexHeader header = dexFile.dexHeader_;
        List<TypeItem> typeItemsList = new ArrayList<TypeItem>();
        for(int i =0; i < header.type_ids_size_;i++){
            int base  = header.type_ids_off_ + TypeItem.size * i;
            TypeItem typeItem = new TypeItem(base, TypeItem.size);
            byte[] bs = Util.copyByte(dexBytes, header.type_ids_off_ + TypeItem.size * i , TypeItem.size);
            typeItem.type_idx_ = Util.byte2Short(bs);
            typeItemsList.add(typeItem);
        }
        dexFile.typeItemsList = typeItemsList;
        return true;
    }

    private  ProtoId parseParameterTypeList(int startOff, ProtoId item){
        byte[] sizeByte = Util.copyByte(dexBytes, startOff, 4);
        int size = Util.byte2Int(sizeByte);
        List<String> parametersList = new ArrayList<String>();
        List<Short> typeList = new ArrayList<Short>(size);
        for(int i=0;i<size;i++){
            byte[] typeByte = Util.copyByte(dexBytes, startOff+4+2*i, 2);
            typeList.add(Util.byte2Short(typeByte));
        }
        for(int i=0;i<typeList.size();i++){
            int index = dexFile.typeItemsList.get(typeList.get(i)).type_idx_;
            parametersList.add(dexFile.stringsList.get(index));
        }

        item.size_ = size;
        item.parametersList = parametersList;

        return item;
    }

    private boolean parseProtoIds() {
        DexHeader header = dexFile.dexHeader_;
        List<ProtoId> protoIdsList = new ArrayList<ProtoId>();
        for (int i = 0; i < header.proto_ids_size_; i++) {
            int base = header.proto_ids_off_ + ProtoId.size * i;
            ProtoId protoId = new ProtoId(base, ProtoId.size);
            byte[] shorty_idx_ = Util.copyByte(dexBytes, base, 4);
            byte[] return_type_idx_ = Util.copyByte(dexBytes, base + 4, 2);
            byte[] pad_ = Util.copyByte(dexBytes, base + 6, 2);
            byte[] parameters_off_ = Util.copyByte(dexBytes, base + 8, 4);
            protoId.shorty_idx_ = Util.byte2Int(shorty_idx_);
            protoId.return_type_idx_ = Util.byte2Short(return_type_idx_);
            protoId.pad_ = Util.byte2Short(pad_);
            protoId.parameters_off_ = Util.byte2Int(parameters_off_);
            protoIdsList.add(protoId);
        }
        dexFile.protoIdsList = protoIdsList;
        for(ProtoId item : protoIdsList) {
            //DbgLog.dbgprint("proto:" + dexFile.stringsList.get(item.shorty_idx_) + "," + dexFile.stringsList.get(item.return_type_idx_));
            if (item.parameters_off_ != 0) {
                item = parseParameterTypeList(item.parameters_off_, item);
            }
        }
        return true;
    }

    private boolean parseFieldIds(){
        DexHeader header = dexFile.dexHeader_;
        List<FieldId> fieldIdsList = new ArrayList<FieldId>();
        for (int i = 0; i < header.field_ids_size_; i++){
            int base = header.field_ids_off_ + FieldId.size * i;
            FieldId  fieldId = new FieldId(base, FieldId.size);
            byte[] class_idx_ = Util.copyByte(dexBytes, base, 2);
            byte[] type_idx_ = Util.copyByte(dexBytes, base + 2, 2);
            byte[] name_idx_ = Util.copyByte(dexBytes, base + 6, 4);
            fieldId.class_idx_ = Util.byte2Short(class_idx_);
            fieldId.type_idx_ = Util.byte2Short(type_idx_);
            fieldId.name_idx_ = Util.byte2Int(name_idx_);
            fieldIdsList.add(fieldId);
        }
        dexFile.fieldIdsList = fieldIdsList;
        return true;
    }
    private boolean parseMethodIds(){
        DexHeader header = dexFile.dexHeader_;
        List<MethodId> methodIdsList = new ArrayList<MethodId>();
        for (int i = 0; i < header.method_ids_size_; i++){
            int base = header.method_ids_off_ + MethodId.size * i;
            MethodId  methodId = new MethodId(base, MethodId.size);
            byte[] class_idx_ = Util.copyByte(dexBytes, base, 2);
            byte[] proto_idx_ = Util.copyByte(dexBytes, base + 2, 2);
            byte[] name_idx_ = Util.copyByte(dexBytes, base + 4, 4);
            methodId.class_idx_ = Util.byte2Short(class_idx_);
            methodId.proto_idx_ = Util.byte2Short(proto_idx_);
            methodId.name_idx_ = Util.byte2Int(name_idx_);
            methodIdsList.add(methodId);
        }
        dexFile.methodIdsList = methodIdsList;
        return true;
    }
    private boolean parseClassDefs(){
        DexHeader header = dexFile.dexHeader_;
        List<ClassDef> classDefsList = new ArrayList<ClassDef>();
        for (int i = 0; i < header.class_defs_size_; i++){
            int base = header.class_defs_off_ + ClassDef.size * i;
            ClassDef  classDef = new ClassDef(base, ClassDef.size);
            byte[] class_idx_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i, 2);
            byte[] pad1_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 2, 2);
            byte[] access_flags_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 4, 4);
            byte[] superclass_idx_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 8, 2);
            byte[] pad2_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 10, 2);
            byte[] interfaces_off_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 12, 4);
            byte[] source_file_idx_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 16, 4);
            byte[] annotations_off_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 20, 4);
            byte[] class_data_off_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 24, 4);
            byte[] static_values_off_ = Util.copyByte(dexBytes, header.class_defs_off_ + ClassDef.size * i + 28, 4);

            classDef.class_idx_ = Util.byte2Short(class_idx_);
            classDef.pad1_ = Util.byte2Short(pad1_);
            classDef.access_flags_ = Util.byte2Int(access_flags_);
            classDef.superclass_idx_ = Util.byte2Short(superclass_idx_);
            classDef.pad2_ = Util.byte2Short(pad2_);
            classDef.interfaces_off_ = Util.byte2Int(interfaces_off_);
            classDef.source_file_idx_ = Util.byte2Int(source_file_idx_);
            classDef.annotations_off_ = Util.byte2Int(annotations_off_);
            classDef.class_data_off_ = Util.byte2Int(class_data_off_);
            classDef.static_values_off_ = Util.byte2Int(static_values_off_);
            classDefsList.add(classDef);
        }
        dexFile.classDefsList = classDefsList;
        HashMap<String, ClassDef> classDataMap = new HashMap();
        for(ClassDef item : classDefsList){
          //  DbgLog.dbgprint("item:"+item);
            int classIdx = item.class_idx_;
            TypeItem typeItem = dexFile.typeItemsList.get(classIdx);
           // DbgLog.dbgprint("classIdx:"+dexFile.stringsList.get(typeItem.type_idx_));
            int superClassIdx = item.superclass_idx_;
            TypeItem superTypeItem = dexFile.typeItemsList.get(superClassIdx);
          //  DbgLog.dbgprint("superitem:"+dexFile.stringsList.get(superTypeItem.type_idx_));
            int sourceIdx = item.source_file_idx_;
            if(sourceIdx == -1 || sourceIdx == 0){
                continue;
            }
            String sourceFile = dexFile.stringsList.get(sourceIdx);
            //DbgLog.dbgprint("sourceFile:"+sourceFile);

            classDataMap.put(classIdx+"", item);
        }
        dexFile.classDataMap = classDataMap;
        return true;
    }

//    private boolean parseMapItems(){
//        DexHeader header = dexFile.dexHeader_;
//        int base = header.map_off_;
//        MapList list = new MapList(base, 0);
//        byte[] size_ = Util.copyByte(dexBytes, base, 4);
//        list.size_ = Util.byte2Int(size_);
//        list.dataSize = 4 + list.size_ * MapItem.size;
//        base += 4;
//        List<MapItem> mapItemList = new ArrayList<>();
//        for(int i = 0; i< list.size_; i++){
//            MapItem mapItem = new MapItem(base, MapItem.size);
//            byte[] type_ = Util.copyByte(dexBytes, base, 2);
//            byte[] unused_ = Util.copyByte(dexBytes, base+2, 2);
//            byte[] size__ = Util.copyByte(dexBytes, base+4, 4);
//            byte[] offset_ = Util.copyByte(dexBytes, base+8, 4);
//            mapItem.type_ = Util.byte2Short(type_);
//            mapItem.unused_ = Util.byte2Short(unused_);
//            mapItem.size_ = Util.byte2Int(size__);
//            mapItem.offset_ = Util.byte2Int(offset_);
//            mapItemList.add(mapItem);
//        }
//        list.list_ = mapItemList;
//        return true;
//    }



    private ClassDataItem parseClassDataItem(int offset){
        if (offset == 0){
            return null;
        }
        ClassDataItem item = new ClassDataItem(offset, ClassDataItem.size);
        for(int i=0;i<4;i++){
            byte[] byteAry = Util.readUnsignedLeb128(dexBytes, offset);
            offset += byteAry.length;
            int size = 0;
            if(byteAry.length == 1){
                size = byteAry[0];
            }else if(byteAry.length == 2){
                size = Util.byte2Short(byteAry);
            }else if(byteAry.length == 4){
                size = Util.byte2Int(byteAry);
            }
            if(i == 0){
                item.static_fields_size = size;
            }else if(i == 1){
                item.instance_fields_size = size;
            }else if(i == 2){
                item.direct_methods_size = size;
            }else if(i == 3){
                item.virtual_methods_size = size;
            }
        }


        EncodedField[] staticFieldAry = new EncodedField[item.static_fields_size];
        for(int i=0;i<item.static_fields_size;i++){
            /**
             *  public int filed_idx_diff;
             public int access_flags;
             */
            EncodedField staticField = new EncodedField(offset, 0);
            staticField.filed_idx_diff = Util.readUnsignedLeb128(dexBytes, offset);
            offset += staticField.filed_idx_diff.length;
            staticField.access_flags = Util.readUnsignedLeb128(dexBytes, offset);
            offset += staticField.access_flags.length;
            staticFieldAry[i] = staticField;
        }

        EncodedField[] instanceFieldAry = new EncodedField[item.instance_fields_size];
        for(int i=0;i<item.instance_fields_size;i++){
            /**
             *  public int filed_idx_diff;
             public int access_flags;
             */
            EncodedField instanceField = new EncodedField(offset, 0);
            instanceField.filed_idx_diff = Util.readUnsignedLeb128(dexBytes, offset);
            offset += instanceField.filed_idx_diff.length;
            instanceField.access_flags = Util.readUnsignedLeb128(dexBytes, offset);
            offset += instanceField.access_flags.length;
            instanceFieldAry[i] = instanceField;
        }

        EncodedMethod[] staticMethodsAry = new EncodedMethod[item.direct_methods_size];
        for(int i=0;i<item.direct_methods_size;i++){
            /**
             *  public byte[] method_idx_diff;
             public byte[] access_flags;
             public byte[] code_off;
             */
            EncodedMethod directMethod = new EncodedMethod(offset, 0);
            directMethod.method_idx_diff = Util.readUnsignedLeb128(dexBytes, offset);
            offset += directMethod.method_idx_diff.length;
            directMethod.access_flags = Util.readUnsignedLeb128(dexBytes, offset);
            offset += directMethod.access_flags.length;
            directMethod.code_off = Util.readUnsignedLeb128(dexBytes, offset);
            offset += directMethod.code_off.length;
            staticMethodsAry[i] = directMethod;
        }

        EncodedMethod[] instanceMethodsAry = new EncodedMethod[item.virtual_methods_size];
        for(int i=0;i<item.virtual_methods_size;i++){
            /**
             *  public byte[] method_idx_diff;
             public byte[] access_flags;
             public byte[] code_off;
             */
            EncodedMethod instanceMethod = new EncodedMethod(offset, 0);
            instanceMethod.method_idx_diff = Util.readUnsignedLeb128(dexBytes, offset);
            offset += instanceMethod.method_idx_diff.length;
            instanceMethod.access_flags = Util.readUnsignedLeb128(dexBytes, offset);
            offset += instanceMethod.access_flags.length;
            instanceMethod.code_off = Util.readUnsignedLeb128(dexBytes, offset);
            offset += instanceMethod.code_off.length;
            instanceMethodsAry[i] = instanceMethod;
        }

        item.static_fields = staticFieldAry;
        item.instance_fields = instanceFieldAry;
        item.direct_methods = staticMethodsAry;
        item.virtual_methods = instanceMethodsAry;

        return item;
    }
    private boolean parseClassDatas(){
        List<ClassDataItem> dataItemsList = new ArrayList();
        for(String key : dexFile.classDataMap.keySet()){
            int dataOffset = dexFile.classDataMap.get(key).class_data_off_;
            //DbgLog.dbgprint("data offset:"+Util.bytesToHexString(Util.int2Byte(dataOffset)));
            ClassDataItem item = parseClassDataItem(dataOffset);
            if (item != null)
                dataItemsList.add(item);
            //DbgLog.dbgprint("class item:"+item);
        }
        dexFile.dataItemsList = dataItemsList;
        return true;
    }



    private  CodeItem parseCodeItem(int offset){
        if (offset == 0){
            return null;
        }

        CodeItem item = new CodeItem(offset ,0);

        /**
         *  public short registers_size;
         public short ins_size;
         public short outs_size;
         public short tries_size;
         public int debug_info_off;
         public int insns_size;
         public short[] insns;
         */
        byte[] regSizeByte = Util.copyByte(dexBytes, offset, 2);
        byte[] insSizeByte = Util.copyByte(dexBytes, offset+2, 2);
        byte[] outsSizeByte = Util.copyByte(dexBytes, offset+4, 2);
        byte[] triesSizeByte = Util.copyByte(dexBytes, offset+6, 2);
        byte[] debugInfoByte = Util.copyByte(dexBytes, offset+8, 4);
        byte[] insnsSizeByte = Util.copyByte(dexBytes, offset+12, 4);
        item.registers_size_ = Util.byte2Short(regSizeByte);
        item.ins_size_ = Util.byte2Short(insSizeByte);
        item.outs_size_ = Util.byte2Short(outsSizeByte);
        item.tries_size_ = Util.byte2Short(triesSizeByte);
        item.debug_info_off_ = Util.byte2Int(debugInfoByte);
        item.insns_size_in_code_units_ = Util.byte2Int(insnsSizeByte);

//        if (item.insns_size_in_code_units_ > 10000){
//            DbgLog.dbgprint("sds");
//        }
        short[] insnsAry = new short[item.insns_size_in_code_units_];
        int aryOffset = offset + 16;
        for(int i=0;i<item.insns_size_in_code_units_;i++){
            byte[] insnsByte = Util.copyByte(dexBytes, aryOffset+i*2, 2);
            insnsAry[i] = Util.byte2Short(insnsByte);
        }
        item.insns_ = insnsAry;
        item.dataSize = 16 + item.insns_size_in_code_units_ * 2;
        return item;
    }
    public boolean parseCode(){
        dexFile.directMethodCodeItemsList = new ArrayList();
        dexFile.virtualMethodCodeItemsList = new ArrayList();
        for(ClassDataItem item : dexFile.dataItemsList){
            for(EncodedMethod item1 : item.direct_methods){
                int offset = Util.decodeUleb128(item1.code_off);

                CodeItem items = parseCodeItem(offset);
                if (items!=null)
                    dexFile.directMethodCodeItemsList.add(items);
                //DbgLog.dbgprint("direct method item:"+items);
            }

            for(EncodedMethod item1 : item.virtual_methods){
                int offset = Util.decodeUleb128(item1.code_off);
                CodeItem items = parseCodeItem(offset);
                if (items!=null)
                    dexFile.virtualMethodCodeItemsList.add(items);
                //DbgLog.dbgprint("virtual method item:"+items);
            }
        }
        return true;
    }

    private static CodeItem decryptOneMethod(CodeItem method){
        //we can use other encrypt ways
        short[] orignCode = method.insns_;
        for (int i = 0; i< method.insns_size_in_code_units_; i++){
            //fixme
            orignCode[i] += 1;
        }
        return method;
    }
    public void decryptAllMethods(){
        //encryptall methods
        for (CodeItem method : dexFile.directMethodCodeItemsList){
            decryptOneMethod(method);
            byte[] changedBytes = method.getCodeBytes();
            Util.byteCover(dexBytes, changedBytes, method.dataBase+16);
        }

        for (CodeItem method : dexFile.virtualMethodCodeItemsList){
            decryptOneMethod(method);
            byte[] changedBytes = method.getCodeBytes();
            Util.byteCover(dexBytes, changedBytes, method.dataBase+16);
        }
    }
    private static CodeItem encryptOneMethod(CodeItem method){
        //we can use other encrypt ways
        short[] orignCode = method.insns_;
        for (int i = 0; i< method.insns_size_in_code_units_; i++){
            //fixme
            orignCode[i] -= 1;
        }
        return method;
    }
    public boolean encryptAllMethods(){
        //encryptall methods
        for (CodeItem method : dexFile.directMethodCodeItemsList){
            encryptOneMethod(method);
            byte[] changedBytes = method.getCodeBytes();
            Util.byteCover(dexBytes, changedBytes, method.dataBase+16);
        }

        for (CodeItem method : dexFile.virtualMethodCodeItemsList){
            encryptOneMethod(method);
            byte[] changedBytes = method.getCodeBytes();
            Util.byteCover(dexBytes, changedBytes, method.dataBase+16);
        }
        return true;
    }


    private void fixCheckSumHeader() {
        Adler32 adler = new Adler32();
        adler.update(dexBytes, 12, dexBytes.length-12);

        long value = adler.getValue();
        int va = (int) value;
        byte[] newcs = Util.int2Byte(va);
        byte[] recs = new byte[4];
        for (int i = 0; i < 4; i++) {
            recs[i] = newcs[newcs.length - 1 - i];
//            DbgLog.dbgprint(Integer.toHexString(newcs[i]));
        }
        Util.byteCover(dexBytes, newcs, 8);
        DbgLog.dbgprint(Long.toHexString(value));
    }



    private void fixSHA1Header()
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(dexBytes, 32, dexBytes.length - 32);
        byte[] newdt = md.digest();
        //System.arraycopy(newdt, 0, dexBytes, 12, 20);
        String hexstr = "";
        for (int i = 0; i < newdt.length; i++) {
            hexstr += Integer.toString((newdt[i] & 0xff) + 0x100, 16)
                    .substring(1);
        }
        Util.byteCover(dexBytes, newdt, 12);
        DbgLog.dbgprint(hexstr);
    }

    public boolean writeToFile(String path){
        try {
            fixSHA1Header();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        fixCheckSumHeader();

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

            fop.write(dexBytes);
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
