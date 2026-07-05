/*
 * opendnp3_force_crc.h — Force CRC validation ON in AFL++ builds.
 *
 * afl-clang-fast++ auto-defines FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION,
 * which causes OpenDNP3's CRC::IsCorrectCRC() to return true unconditionally.
 * This header is force-included (-include) to #undef that macro AFTER the
 * compiler defines it but BEFORE any source code sees it.
 */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#undef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#endif
