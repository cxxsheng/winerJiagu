//
// Created by winer on 2019/2/11.
//

#ifndef PROXYAPP_LEB128_H
#define PROXYAPP_LEB128_H
#include <stdint.h>


# define LIKELY(x)	__builtin_expect(!!(x), 1)
# define UNLIKELY(x)	__builtin_expect(!!(x), 0)

uint32_t DecodeUnsignedLeb128(const uint8_t** data) {
  const uint8_t* ptr = *data;
  int result = *(ptr++);
  if (UNLIKELY(result > 0x7f)) {
    int cur = *(ptr++);
    result = (result & 0x7f) | ((cur & 0x7f) << 7);
    if (cur > 0x7f) {
      cur = *(ptr++);
      result |= (cur & 0x7f) << 14;
      if (cur > 0x7f) {
        cur = *(ptr++);
        result |= (cur & 0x7f) << 21;
        if (cur > 0x7f) {
          // Note: We don't check to see if cur is out of range here,
          // meaning we tolerate garbage in the four high-order bits.
          cur = *(ptr++);
          result |= cur << 28;
        }
      }
    }
  }
  *data = ptr;
  return (uint32_t)(result);
}

int32_t DecodeSignedLeb128(const uint8_t** data) {
  const uint8_t* ptr = *data;
  int32_t result = *(ptr++);
  if (result <= 0x7f) {
    result = (result << 25) >> 25;
  } else {
    int cur = *(ptr++);
    result = (result & 0x7f) | ((cur & 0x7f) << 7);
    if (cur <= 0x7f) {
      result = (result << 18) >> 18;
    } else {
      cur = *(ptr++);
      result |= (cur & 0x7f) << 14;
      if (cur <= 0x7f) {
        result = (result << 11) >> 11;
      } else {
        cur = *(ptr++);
        result |= (cur & 0x7f) << 21;
        if (cur <= 0x7f) {
          result = (result << 4) >> 4;
        } else {
          // Note: We don't check to see if cur is out of range here,
          // meaning we tolerate garbage in the four high-order bits.
          cur = *(ptr++);
          result |= cur << 28;
        }
      }
    }
  }
  *data = ptr;
  return result;
}


inline uint32_t UnsignedLeb128Size(uint32_t data) {
  // bits_to_encode = (data != 0) ? 32 - CLZ(x) : 1  // 32 - CLZ(data | 1)
  // bytes = ceil(bits_to_encode / 7.0);             // (6 + bits_to_encode) / 7
  uint32_t x = 6 + 32 - CLZ(data | 1);
  // Division by 7 is done by (x * 37) >> 8 where 37 = ceil(256 / 7).
  // This works for 0 <= x < 256 / (7 * 37 - 256), i.e. 0 <= x <= 85.
  return (x * 37) >> 8;
}

#endif //PROXYAPP_LEB128_H
