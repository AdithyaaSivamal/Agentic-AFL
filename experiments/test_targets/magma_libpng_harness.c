/*
 * magma_libpng_harness.c — AFL++ harness for libpng's IHDR CRC-32 wall.
 *
 * Reads a PNG file from argv[1] and attempts a full decode via libpng.
 * Prints PNG_DECODE_OK only if the decode completes without error —
 * in particular, a CRC-32 mismatch on the IHDR chunk triggers libpng's
 * longjmp-based error path (see png_crc_finish / png_chunk_error in
 * pngrutil.c), caught here via setjmp(png_jmpbuf(png_ptr)).
 *
 * Adapted from OSS-Fuzz's libpng_read_fuzzer, using libpng's standard
 * FILE*-based I/O (png_init_io) instead of a custom in-memory read
 * callback, since input arrives as a file path (AFL++'s @@ convention)
 * rather than an in-memory buffer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include "png.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <png_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 1;
    }

    png_structp png_ptr = png_create_read_struct(
        PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        fclose(fp);
        return 1;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        fclose(fp);
        return 1;
    }

    /* libpng reports errors via longjmp, not return codes. Any error
     * during png_read_png() — including an IHDR CRC-32 mismatch —
     * jumps back to here with a non-zero setjmp return. We must not
     * print the accept marker in that case. */
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        fclose(fp);
        return 1;
    }

    png_init_io(png_ptr, fp);
    png_read_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
    fclose(fp);

    printf("PNG_DECODE_OK\n");
    return 0;
}
