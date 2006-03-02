/*
 * UTF-8 support routines
 *
 * Copyright 2000 Alexandre Julliard
 * 
 * Taken from WINE, so the usual WINE copyright applies:
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include <ole2.h>

/* number of following bytes in sequence based on first byte value (for bytes above 0x7f) */
static const char utf8_length[128] =
{
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x80-0x8f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x90-0x9f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0xa0-0xaf */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0xb0-0xbf */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xc0-0xcf */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xd0-0xdf */
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, /* 0xe0-0xef */
    3,3,3,3,3,3,3,3,4,4,4,4,5,5,0,0  /* 0xf0-0xff */
};

/* first byte mask depending on UTF-8 sequence length */
static const unsigned char utf8_mask[6] = { 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

/* minimum Unicode value depending on UTF-8 sequence length */
static const unsigned int utf8_minval[6] = { 0x0, 0x80, 0x800, 0x10000, 0x200000, 0x4000000 };


/* query necessary dst length for src string */
inline static int get_length_wcs_utf8( const WCHAR *src, unsigned int srclen )
{
    int len;

    for (len = 0; srclen; srclen--, src++, len++)
    {
        if (*src >= 0x80)
        {
            len++;
            if (*src >= 0x800) len++;
        }
    }
    return len;
}

/* wide char to UTF-8 string conversion */
/* return -1 on dst buffer overflow */
int utf8_wcstombs( const WCHAR *src, int srclen, char *dst, int dstlen )
{
    char *orig_dst = dst;

    if (!dstlen) return get_length_wcs_utf8( src, srclen );

    for (; srclen; srclen--, src++)
    {
        WCHAR ch = *src;

        if (ch < 0x80)  /* 0x00-0x7f: 1 byte */
        {
            if (!dstlen--) return -1;  /* overflow */
            *dst++ = ch;
            continue;
        }

        if (ch < 0x800)  /* 0x80-0x7ff: 2 bytes */
        {
            if ((dstlen -= 2) < 0) return -1;  /* overflow */
            dst[1] = 0x80 | (ch & 0x3f);
            ch >>= 6;
            dst[0] = 0xc0 | ch;
            dst += 2;
            continue;
        }

        /* 0x800-0xffff: 3 bytes */

        if ((dstlen -= 3) < 0) return -1;  /* overflow */
        dst[2] = 0x80 | (ch & 0x3f);
        ch >>= 6;
        dst[1] = 0x80 | (ch & 0x3f);
        ch >>= 6;
        dst[0] = 0xe0 | ch;
        dst += 3;
    }
    return dst - orig_dst;
}

/* query necessary dst length for src string */
inline static int get_length_mbs_utf8( const unsigned char *src, int srclen )
{
    int ret;
    const unsigned char *srcend = src + srclen;

    for (ret = 0; src < srcend; ret++)
    {
        unsigned char ch = *src++;
        if (ch < 0xc0) continue;

        switch(utf8_length[ch-0x80])
        {
        case 5:
            if (src >= srcend) return ret;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) continue;
            src++;
        case 4:
            if (src >= srcend) return ret;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) continue;
            src++;
        case 3:
            if (src >= srcend) return ret;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) continue;
            src++;
        case 2:
            if (src >= srcend) return ret;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) continue;
            src++;
        case 1:
            if (src >= srcend) return ret;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) continue;
            src++;
        }
    }
    return ret;
}

/* UTF-8 to wide char string conversion */
/* return -1 on dst buffer overflow, -2 on invalid input char */
int utf8_mbstowcs( int flags, const char *src, int srclen, WCHAR *dst, int dstlen )
{
    int len, count;
    unsigned int res;
    const char *srcend = src + srclen;

    if (!dstlen) return get_length_mbs_utf8( src, srclen );

    for (count = dstlen; count && (src < srcend); count--, dst++)
    {
        unsigned char ch = *src++;
        if (ch < 0x80)  /* special fast case for 7-bit ASCII */
        {
            *dst = ch;
            continue;
        }
        len = utf8_length[ch-0x80];
        res = ch & utf8_mask[len];

        switch(len)
        {
        case 5:
            if (src >= srcend) goto done;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) goto bad;
            res = (res << 6) | ch;
            src++;
        case 4:
            if (src >= srcend) goto done;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) goto bad;
            res = (res << 6) | ch;
            src++;
        case 3:
            if (src >= srcend) goto done;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) goto bad;
            res = (res << 6) | ch;
            src++;
        case 2:
            if (src >= srcend) goto done;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) goto bad;
            res = (res << 6) | ch;
            src++;
        case 1:
            if (src >= srcend) goto done;  /* ignore partial char */
            if ((ch = *src ^ 0x80) >= 0x40) goto bad;
            res = (res << 6) | ch;
            src++;
            if (res < utf8_minval[len]) goto bad;
            if (res >= 0x10000) goto bad;  /* FIXME: maybe we should do surrogates here */
            *dst = res;
            continue;
        }
    bad:
        if (flags & MB_ERR_INVALID_CHARS) return -2;  /* bad char */
        *dst = (WCHAR)'?';
    }
    if (src < srcend) return -1;  /* overflow */
done:
    return dstlen - count;
}


int
bstrtoutf8 ( BSTR src, char *dst, size_t dstlen )
{
    size_t srclen, needed;
    int n;

    srclen = src? SysStringLen (src): 0;

    needed = srclen? (utf8_wcstombs (src, srclen, NULL, 0) + 1) : 1;
    if (!dst || !dstlen)
        return needed;
    if (dstlen < needed)
        return -1;
    if (srclen) {
        n = utf8_wcstombs (src, srclen, dst, dstlen);
        if (n < 0)
            return -1;
    }
    else 
        n = 0;
    dst[n] = 0;
    return n;
}



