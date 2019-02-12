/*
3/1/2019
Translate from art/runtime/dex_file.h by winer.
*/
package com.winer.parser;

import org.omg.CORBA.DATA_CONVERSION;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DexFile {
//    final public static  byte kDexMagic[] = { 'd', 'e', 'x', '\n' };
//    final public static  byte kDexMagicVersion[] = { '0', '3', '5', '\0' };
//    final public static int kSha1DigestSize = 20;
//    final static  int kDexEndianConstant = 0x12345678;
//    final static int kDexNoIndex = 0xFFFFFFFF;
//    final static int kDexNoIndex16 = 0xFFFF;
//    final static char kMultiDexSeparator = ':';
    public DexHeader dexHeader_ ;
    public List<StringId> stringIdsList;
    public  List<String> stringsList ;

    public  List<MapItem> mapItemsList;

    public  List<TypeItem> typeItemsList;
    public  List<ProtoId> protoIdsList;
    public  List<FieldId> fieldIdsList;
    public  List<MethodId> methodIdsList;
    public  List<ClassDef> classDefsList;

    public  List<ClassDataItem> dataItemsList;

    public  List<CodeItem> directMethodCodeItemsList ;
    public  List<CodeItem> virtualMethodCodeItemsList ;


    //这里的map用来存储code数据，因为一个ClassCode都是以class_idx为单位的，所以这里的key就是classname来存储
    public HashMap<String, ClassDef> classDataMap;
}
class Data{
    public int dataBase;
    public int dataSize;
    public Data(int base, int size){
        dataBase = base;
        dataSize = size;
    }
}
class DexHeader extends Data{
    final public static  int size = 112;

    final public static byte kDexMagic[] = { 'd', 'e', 'x', '\n' };
    final public static byte kDexMagicVersion[] = { '0', '3', '5', '\0' };
    final public static int kSha1DigestSize = 20;

    public int base;

    public byte[] magic = new byte[8];
    public int checksum_;  // See also location_checksum_
    public byte[] signature_ = new byte[kSha1DigestSize];
    public int file_size_;  // size of entire file
    public int header_size_;  // offset to start of next section
    public int endian_tag_;
    public int link_size_;  // unused
    public int link_off_;  // unused
    public int map_off_;  // map
    public int string_ids_size_;  // number of StringIds
    public int string_ids_off_;  // file offset of StringIds array
    public int type_ids_size_;  // number of TypeIds, we don't support more than 65535
    public int type_ids_off_;  // file offset of TypeIds array
    public int proto_ids_size_;  // number of ProtoIds, we don't support more than 65535
    public int proto_ids_off_;  // file offset of ProtoIds array
    public int field_ids_size_;  // number of FieldIds
    public int field_ids_off_;  // file offset of FieldIds array
    public int method_ids_size_;  // number of MethodIds
    public int method_ids_off_;  // file offset of MethodIds array
    public int class_defs_size_;  // number of ClassDefs
    public int class_defs_off_;  // file offset of ClassDef array
    public int data_size_;  // unused
    public int data_off_;  // unused

    public DexHeader(int base, int size) {
        super(base, size);
    }
}

class MapItem extends Data{
    // Map item type codes.
    final public static  int size = 2+2+4+4;

    final public static int kDexTypeHeaderItem               = 0x0000;
    final public static int kDexTypeStringIdItem             = 0x0001;
    final public static int kDexTypeTypeIdItem               = 0x0002;
    final public static int kDexTypeProtoIdItem              = 0x0003;
    final public static int kDexTypeFieldIdItem              = 0x0004;
    final public static int kDexTypeMethodIdItem             = 0x0005;
    final public static int kDexTypeClassDefItem             = 0x0006;
    final public static int kDexTypeMapList                  = 0x1000;
    final public static int kDexTypeTypeList                 = 0x1001;
    final public static int kDexTypeAnnotationSetRefList     = 0x1002;
    final public static int kDexTypeAnnotationSetItem        = 0x1003;
    final public static int kDexTypeClassDataItem            = 0x2000;
    final public static int kDexTypeCodeItem                 = 0x2001;
    final public static int kDexTypeStringDataItem           = 0x2002;
    final public static int kDexTypeDebugInfoItem            = 0x2003;
    final public static int kDexTypeAnnotationItem           = 0x2004;
    final public static int kDexTypeEncodedArrayItem         = 0x2005;
    final public static int kDexTypeAnnotationsDirectoryItem = 0x2006;


    public short type_;
    public short  unused_;
    public int  size_;
    public int offset_;

    public MapItem(int base, int size) {
        super(base, size);
    }
}

class MapList extends Data {
        public int size_;
        List<MapItem> list_;

        public MapList(int base, int size) {
            super(base, size);
        }
}

class StringId extends Data{
    final public static  int size = 4;

    public  int string_data_off_;

    public StringId(int base, int size) {
        super(base, size);
    }
}

class FieldId extends Data{
        final public static  int size = 2+2+4;

        public short class_idx_;  // index into type_ids_ array for defining class
        public short  type_idx_;  // index into type_ids_ array for field type
        public int name_idx_;  // index into string_ids_ array for field name

    public FieldId(int base, int size) {
        super(base, size);
    }
}

class MethodId extends Data{
        final public static  int size = 2+2+4;

        public short class_idx_;  // index into type_ids_ array for defining class
        public short proto_idx_;  // index into proto_ids_ array for method prototype
        public int name_idx_;  // index into string_ids_ array for method name

    public MethodId(int base, int size) {
        super(base, size);
    }
}


class ProtoId extends Data{
        final public static  int size = 4+2+2+4;

        public int shorty_idx_;  // index into string_ids array for shorty descriptor
        public short return_type_idx_;  // index into type_ids array for return type
        public short pad_;             // padding = 0
        public int parameters_off_;  // file offset to type_list for parameter types
        //these vars are not in this struct but are pointed by the parameters_off_
        public int size_;
        public List<String> parametersList;

        public ProtoId(int base, int size) {
        super(base, size);
    }
};
class ClassDef extends Data{
          final public static  int size = 2*4 + 4*6;

          public short class_idx_;  // index into type_ids_ array for this class
          public short pad1_;  // padding = 0
          public int access_flags_;
          public short superclass_idx_;  // index into type_ids_ array for superclass
          public short pad2_;  // padding = 0
          public int interfaces_off_;  // file offset to TypeList
          public int source_file_idx_;  // index into string_ids_ for source file name
          public int annotations_off_;  // file offset to annotations_directory_item
          public int class_data_off_;  // file offset to class_data_item
          public int static_values_off_;  // file offset to EncodedArray

        public ClassDef(int base, int size) {
            super(base, size);
    }

//          // Returns the valid access flags, that is, Java modifier bits relevant to the ClassDef type
//          // (class or interface). These are all in the lower 16b and do not contain runtime flags.
//          public int GetJavaAccessFlags() const {
//          // Make sure that none of our runtime-only flags are set.
//          COMPILE_ASSERT((kAccValidClassFlags & kAccJavaFlagsMask) == kAccValidClassFlags,
//          valid_class_flags_not_subset_of_java_flags);
//          COMPILE_ASSERT((kAccValidInterfaceFlags & kAccJavaFlagsMask) == kAccValidInterfaceFlags,
//          valid_interface_flags_not_subset_of_java_flags);
//
//          if ((access_flags_ & kAccInterface) != 0) {
//          // Interface.
//          return access_flags_ & kAccValidInterfaceFlags;
//          } else {
//          // Class.
//          return access_flags_ & kAccValidClassFlags;
//          }
//          }
}

class TypeItem extends Data{
        final public static  int size = 2;

        public short type_idx_;  // index into type_ids section

        public TypeItem(int base, int size) {
            super(base, size);
         }
}


class TypeList{
        //fixme
}

class CodeItem extends Data{

        //final public static  int size = 2*4+4*2;

        public short registers_size_;
        public short ins_size_;
        public short outs_size_;
        public short tries_size_;
        public int debug_info_off_;  // file offset to debug info stream
        public int insns_size_in_code_units_;  // size of the insns array, in 2 byte code units
        public short insns_[];

        public byte[] getCodeBytes(){
            byte[] res = null;
            for (int i = 0; i< insns_size_in_code_units_; i++)
                res = Util.byteMerger(res, Util.short2Byte(insns_[i]));
            if (res.length % 2 == 1)
            {
                return res;
            }
            return res;
        }


        public CodeItem(int base, int size) {
            super(base, size);
        }
};
class EncodedField extends Data{
    public byte[] filed_idx_diff;
    public byte[] access_flags;

    public EncodedField(int base, int size) {
        super(base, size);
    }
}

class EncodedMethod extends Data{
    public byte[] method_idx_diff;
    public byte[] access_flags;
    public byte[] code_off;

    public EncodedMethod(int base, int size) {
        super(base, size);

    }
}
class  ClassDataItem extends Data{
    static public int size = 4+4+4+4;
    public int static_fields_size;
    public int instance_fields_size;
    public int direct_methods_size;
    public int virtual_methods_size;

    public EncodedField[] static_fields;
    public EncodedField[] instance_fields;
    public EncodedMethod[] direct_methods;
    public EncodedMethod[] virtual_methods;

    public ClassDataItem(int base, int size) {
        super(base, size);
    }
}

        // Raw try_item.
class TryItem {
        final public static  int size = 4+2+2;

        public int start_addr_;
        public short insn_count_;
        public short handler_off_;
};



class AnnotationsDirectoryItem {
        final public static  int size = 16;

        // Annotation constants.
        final public static int kDexVisibilityBuild         = 0x00;     /* annotation visibility */
        final public static int kDexVisibilityRuntime       = 0x01;
        final public static int kDexVisibilitySystem        = 0x02;

        final public static int kDexAnnotationByte          = 0x00;
        final public static int kDexAnnotationShort         = 0x02;
        final public static int kDexAnnotationChar          = 0x03;
        final public static int kDexAnnotationInt           = 0x04;
        final public static int kDexAnnotationLong          = 0x06;
        final public static int kDexAnnotationFloat         = 0x10;
        final public static int kDexAnnotationDouble        = 0x11;
        final public static int kDexAnnotationString        = 0x17;
        final public static int kDexAnnotationType          = 0x18;
        final public static int kDexAnnotationField         = 0x19;
        final public static int kDexAnnotationMethod        = 0x1a;
        final public static int kDexAnnotationEnum          = 0x1b;
        final public static int kDexAnnotationArray         = 0x1c;
        final public static int kDexAnnotationAnnotation    = 0x1d;
        final public static int kDexAnnotationNull          = 0x1e;
        final public static int kDexAnnotationBoolean       = 0x1f;

        final public static int kDexAnnotationValueTypeMask = 0x1f;     /* low 5 bits */
        final public static int kDexAnnotationValueArgShift = 5;

        public int class_annotations_off_;
        public int fields_size_;
        public int methods_size_;
        public int parameters_size_;
};

class FieldAnnotationsItem {
        final public static  int size = 8;

        public int field_idx_;
        public int annotations_off_;

};

class MethodAnnotationsItem {
        final public static  int size = 8;

        public int method_idx_;
        public int annotations_off_;

};

class ParameterAnnotationsItem {
        final public static  int size = 8;

        public int method_idx_;
        public int annotations_off_;

};

class AnnotationSetRefItem {
        final public static  int size = 4;

        public int annotations_off_;

};

class AnnotationSetRefList {
        public int size_;
        AnnotationSetRefItem list_[];
};

class AnnotationSetItem {
        final public static  int size = 8;
        public int size_;
        public int entries_[] ;
};
class AnnotationItem {
        //warning: java char = 2bytes; c char = byte
        public byte visibility_;
        public byte annotation_[];

};